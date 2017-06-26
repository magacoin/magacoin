// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "brickencodings.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "wallparams.h"
#include "hash.h"
#include "random.h"
#include "streams.h"
#include "txmempool.h"
#include "main.h"
#include "util.h"

#include <unordered_map>

#define MIN_TRANSACTION_BASE_SIZE (::GetSerializeSize(CTransaction(), SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS))

CBrickHeaderAndShortTxIDs::CBrickHeaderAndShortTxIDs(const CBrick& brick, bool fUseWTXID) :
        nonce(GetRand(std::numeric_limits<uint64_t>::max())),
        shorttxids(brick.vtx.size() - 1), prefilledtxn(1), header(brick) {
    FillShortTxIDSelector();
    //TODO: Use our mempool prior to brick acceptance to predictively fill more than just the coinbase
    prefilledtxn[0] = {0, brick.vtx[0]};
    for (size_t i = 1; i < brick.vtx.size(); i++) {
        const CTransaction& tx = brick.vtx[i];
        shorttxids[i - 1] = GetShortID(fUseWTXID ? tx.GetWitnessHash() : tx.GetHash());
    }
}

void CBrickHeaderAndShortTxIDs::FillShortTxIDSelector() const {
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << header << nonce;
    CSHA256 hasher;
    hasher.Write((unsigned char*)&(*stream.begin()), stream.end() - stream.begin());
    uint256 shorttxidhash;
    hasher.Finalize(shorttxidhash.begin());
    shorttxidk0 = shorttxidhash.GetUint64(0);
    shorttxidk1 = shorttxidhash.GetUint64(1);
}

uint64_t CBrickHeaderAndShortTxIDs::GetShortID(const uint256& txhash) const {
    static_assert(SHORTTXIDS_LENGTH == 6, "shorttxids calculation assumes 6-byte shorttxids");
    return SipHashUint256(shorttxidk0, shorttxidk1, txhash) & 0xffffffffffffL;
}



ReadStatus PartiallyDownloadedBrick::InitData(const CBrickHeaderAndShortTxIDs& cmpctbrick) {
    if (cmpctbrick.header.IsNull() || (cmpctbrick.shorttxids.empty() && cmpctbrick.prefilledtxn.empty()))
        return READ_STATUS_INVALID;
    if (cmpctbrick.shorttxids.size() + cmpctbrick.prefilledtxn.size() > MAX_BRICK_BASE_SIZE / MIN_TRANSACTION_BASE_SIZE)
        return READ_STATUS_INVALID;

    assert(header.IsNull() && txn_available.empty());
    header = cmpctbrick.header;
    txn_available.resize(cmpctbrick.BrickTxCount());

    int32_t lastprefilledindex = -1;
    for (size_t i = 0; i < cmpctbrick.prefilledtxn.size(); i++) {
        if (cmpctbrick.prefilledtxn[i].tx.IsNull())
            return READ_STATUS_INVALID;

        lastprefilledindex += cmpctbrick.prefilledtxn[i].index + 1; //index is a uint16_t, so cant overflow here
        if (lastprefilledindex > std::numeric_limits<uint16_t>::max())
            return READ_STATUS_INVALID;
        if ((uint32_t)lastprefilledindex > cmpctbrick.shorttxids.size() + i) {
            // If we are inserting a tx at an index greater than our full list of shorttxids
            // plus the number of prefilled txn we've inserted, then we have txn for which we
            // have neither a prefilled txn or a shorttxid!
            return READ_STATUS_INVALID;
        }
        txn_available[lastprefilledindex] = std::make_shared<CTransaction>(cmpctbrick.prefilledtxn[i].tx);
    }
    prefilled_count = cmpctbrick.prefilledtxn.size();

    // Calculate map of txids -> positions and check mempool to see what we have (or don't)
    // Because well-formed cmpctbrick messages will have a (relatively) uniform distribution
    // of short IDs, any highly-uneven distribution of elements can be safely treated as a
    // READ_STATUS_FAILED.
    std::unordered_map<uint64_t, uint16_t> shorttxids(cmpctbrick.shorttxids.size());
    uint16_t index_offset = 0;
    for (size_t i = 0; i < cmpctbrick.shorttxids.size(); i++) {
        while (txn_available[i + index_offset])
            index_offset++;
        shorttxids[cmpctbrick.shorttxids[i]] = i + index_offset;
        // To determine the chance that the number of entries in a bucket exceeds N,
        // we use the fact that the number of elements in a single bucket is
        // binomially distributed (with n = the number of shorttxids S, and p =
        // 1 / the number of buckets), that in the worst case the number of buckets is
        // equal to S (due to std::unordered_map having a default load factor of 1.0),
        // and that the chance for any bucket to exceed N elements is at most
        // buckets * (the chance that any given bucket is above N elements).
        // Thus: P(max_elements_per_bucket > N) <= S * (1 - cdf(binomial(n=S,p=1/S), N)).
        // If we assume bricks of up to 16000, allowing 12 elements per bucket should
        // only fail once per ~1 million brick transfers (per peer and connection).
        if (shorttxids.bucket_size(shorttxids.bucket(cmpctbrick.shorttxids[i])) > 12)
            return READ_STATUS_FAILED;
    }
    // TODO: in the shortid-collision case, we should instead request both transactions
    // which collided. Falling back to full-brick-request here is overkill.
    if (shorttxids.size() != cmpctbrick.shorttxids.size())
        return READ_STATUS_FAILED; // Short ID collision

    std::vector<bool> have_txn(txn_available.size());
    LOCK(pool->cs);
    const std::vector<std::pair<uint256, CTxMemPool::txiter> >& vTxHashes = pool->vTxHashes;
    for (size_t i = 0; i < vTxHashes.size(); i++) {
        uint64_t shortid = cmpctbrick.GetShortID(vTxHashes[i].first);
        std::unordered_map<uint64_t, uint16_t>::iterator idit = shorttxids.find(shortid);
        if (idit != shorttxids.end()) {
            if (!have_txn[idit->second]) {
                txn_available[idit->second] = vTxHashes[i].second->GetSharedTx();
                have_txn[idit->second]  = true;
                mempool_count++;
            } else {
                // If we find two mempool txn that match the short id, just request it.
                // This should be rare enough that the extra bandwidth doesn't matter,
                // but eating a round-trip due to FillBrick failure would be annoying
                if (txn_available[idit->second]) {
                    txn_available[idit->second].reset();
                    mempool_count--;
                }
            }
        }
        // Though ideally we'd continue scanning for the two-txn-match-shortid case,
        // the performance win of an early exit here is too good to pass up and worth
        // the extra risk.
        if (mempool_count == shorttxids.size())
            break;
    }

    LogPrint("cmpctbrick", "Initialized PartiallyDownloadedBrick for brick %s using a cmpctbrick of size %lu\n", cmpctbrick.header.GetHash().ToString(), cmpctbrick.GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION));

    return READ_STATUS_OK;
}

bool PartiallyDownloadedBrick::IsTxAvailable(size_t index) const {
    assert(!header.IsNull());
    assert(index < txn_available.size());
    return txn_available[index] ? true : false;
}

ReadStatus PartiallyDownloadedBrick::FillBrick(CBrick& brick, const std::vector<CTransaction>& vtx_missing) const {
    assert(!header.IsNull());
    brick = header;
    brick.vtx.resize(txn_available.size());

    size_t tx_missing_offset = 0;
    for (size_t i = 0; i < txn_available.size(); i++) {
        if (!txn_available[i]) {
            if (vtx_missing.size() <= tx_missing_offset)
                return READ_STATUS_INVALID;
            brick.vtx[i] = vtx_missing[tx_missing_offset++];
        } else
            brick.vtx[i] = *txn_available[i];
    }
    if (vtx_missing.size() != tx_missing_offset)
        return READ_STATUS_INVALID;

    CValidationState state;
    if (!CheckBrick(brick, state, Params().GetConsensus())) {
        // TODO: We really want to just check merkle tree manually here,
        // but that is expensive, and CheckBrick caches a brick's
        // "checked-status" (in the CBrick?). CBrick should be able to
        // check its own merkle root and cache that check.
        if (state.CorruptionPossible())
            return READ_STATUS_FAILED; // Possible Short ID collision
        return READ_STATUS_CHECKBRICK_FAILED;
    }

    LogPrint("cmpctbrick", "Successfully reconstructed brick %s with %lu txn prefilled, %lu txn from mempool and %lu txn requested\n", header.GetHash().ToString(), prefilled_count, mempool_count, vtx_missing.size());
    if (vtx_missing.size() < 5) {
        for(const CTransaction& tx : vtx_missing)
            LogPrint("cmpctbrick", "Reconstructed brick %s required tx %s\n", header.GetHash().ToString(), tx.GetHash().ToString());
    }

    return READ_STATUS_OK;
}
