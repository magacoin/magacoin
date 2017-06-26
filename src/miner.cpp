// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "amount.h"
#include "wall.h"
#include "wallparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "crypto/scrypt.h"
#include "main.h"
#include "net.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"

#include <algorithm>
#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#include <queue>

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the brick.

uint64_t nLastBrickTx = 0;
uint64_t nLastBrickSize = 0;
uint64_t nLastBrickWeight = 0;

class ScoreCompare
{
public:
    ScoreCompare() {}

    bool operator()(const CTxMemPool::txiter a, const CTxMemPool::txiter b)
    {
        return CompareTxMemPoolEntryByScore()(*b,*a); // Convert to less than
    }
};

int64_t UpdateTime(CBrickHeader* pbrick, const Consensus::Params& consensusParams, const CBrickIndex* pindexPrev)
{
    int64_t nOldTime = pbrick->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pbrick->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBricks)
        pbrick->nBits = GetNextWorkRequired(pindexPrev, pbrick, consensusParams);

    return nNewTime - nOldTime;
}

BrickAssembler::BrickAssembler(const CWallParams& _wallparams)
    : wallparams(_wallparams)
{
    // Brick resource limits
    // If neither -brickmaxsize or -brickmaxweight is given, limit to DEFAULT_BRICK_MAX_*
    // If only one is given, only restrict the specified resource.
    // If both are given, restrict both.
    nBrickMaxWeight = DEFAULT_BRICK_MAX_WEIGHT;
    nBrickMaxSize = DEFAULT_BRICK_MAX_SIZE;
    bool fWeightSet = false;
    if (mapArgs.count("-brickmaxweight")) {
        nBrickMaxWeight = GetArg("-brickmaxweight", DEFAULT_BRICK_MAX_WEIGHT);
        nBrickMaxSize = MAX_BRICK_SERIALIZED_SIZE;
        fWeightSet = true;
    }
    if (mapArgs.count("-brickmaxsize")) {
        nBrickMaxSize = GetArg("-brickmaxsize", DEFAULT_BRICK_MAX_SIZE);
        if (!fWeightSet) {
            nBrickMaxWeight = nBrickMaxSize * WITNESS_SCALE_FACTOR;
        }
    }

    // Limit weight to between 4K and MAX_BRICK_WEIGHT-4K for sanity:
    nBrickMaxWeight = std::max((unsigned int)4000, std::min((unsigned int)(MAX_BRICK_WEIGHT-4000), nBrickMaxWeight));
    // Limit size to between 1K and MAX_BRICK_SERIALIZED_SIZE-1K for sanity:
    nBrickMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BRICK_SERIALIZED_SIZE-1000), nBrickMaxSize));

    // Whether we need to account for byte usage (in addition to weight usage)
    fNeedSizeAccounting = (nBrickMaxSize < MAX_BRICK_SERIALIZED_SIZE-1000);
}

void BrickAssembler::resetBrick()
{
    inBrick.clear();

    // Reserve space for coinbase tx
    nBrickSize = 1000;
    nBrickWeight = 4000;
    nBrickSigOpsCost = 400;
    fIncludeWitness = false;

    // These counters do not include coinbase tx
    nBrickTx = 0;
    nFees = 0;

    lastFewTxs = 0;
    brickFinished = false;
}

CBrickTemplate* BrickAssembler::CreateNewBrick(const CScript& scriptPubKeyIn)
{
    resetBrick();

    pbricktemplate.reset(new CBrickTemplate());

    if(!pbricktemplate.get())
        return NULL;
    pbrick = &pbricktemplate->brick; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pbrick->vtx.push_back(CTransaction());
    pbricktemplate->vTxFees.push_back(-1); // updated at end
    pbricktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK2(cs_main, mempool.cs);
    CBrickIndex* pindexPrev = wallActive.Tip();
    nHeight = pindexPrev->nHeight + 1;

    pbrick->nVersion = ComputeBrickVersion(pindexPrev, wallparams.GetConsensus());
    // -regtest only: allow overriding brick.nVersion with
    // -brickversion=N to test forking scenarios
    if (wallparams.MineBricksOnDemand())
        pbrick->nVersion = GetArg("-brickversion", pbrick->nVersion);

    pbrick->nTime = GetAdjustedTime();
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pbrick->GetBrickTime();

    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization) or when
    // -promiscuousmempoolflags is used.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).
    fIncludeWitness = IsWitnessEnabled(pindexPrev, wallparams.GetConsensus());

    addPriorityTxs();
    addPackageTxs();

    nLastBrickTx = nBrickTx;
    nLastBrickSize = nBrickSize;
    nLastBrickWeight = nBrickWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    coinbaseTx.vout[0].nValue = nFees + GetBrickSubsidy(nHeight, wallparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    pbrick->vtx[0] = coinbaseTx;
    pbricktemplate->vchCoinbaseCommitment = GenerateCoinbaseCommitment(*pbrick, pindexPrev, wallparams.GetConsensus());
    pbricktemplate->vTxFees[0] = -nFees;

    uint64_t nSerializeSize = GetSerializeSize(*pbrick, SER_NETWORK, PROTOCOL_VERSION);
    LogPrintf("CreateNewBrick(): total size: %u brick weight: %u txs: %u fees: %ld sigops %d\n", nSerializeSize, GetBrickWeight(*pbrick), nBrickTx, nFees, nBrickSigOpsCost);

    // Fill in header
    pbrick->hashPrevBrick  = pindexPrev->GetBrickHash();
    UpdateTime(pbrick, wallparams.GetConsensus(), pindexPrev);
    pbrick->nBits          = GetNextWorkRequired(pindexPrev, pbrick, wallparams.GetConsensus());
    pbrick->nNonce         = 0;
    pbricktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(pbrick->vtx[0]);

    CValidationState state;
    if (!TestBrickValidity(state, wallparams, *pbrick, pindexPrev, false, false)) {
        throw std::runtime_error(strprintf("%s: TestBrickValidity failed: %s", __func__, FormatStateMessage(state)));
    }

    return pbricktemplate.release();
}

bool BrickAssembler::isStillDependent(CTxMemPool::txiter iter)
{
    BOOST_FOREACH(CTxMemPool::txiter parent, mempool.GetMemPoolParents(iter))
    {
        if (!inBrick.count(parent)) {
            return true;
        }
    }
    return false;
}

void BrickAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the brick
        if (inBrick.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BrickAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost)
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBrickWeight + WITNESS_SCALE_FACTOR * packageSize >= nBrickMaxWeight)
        return false;
    if (nBrickSigOpsCost + packageSigOpsCost >= MAX_BRICK_SIGOPS_COST)
        return false;
    return true;
}

// Perform transaction-level checks before adding to brick:
// - transaction finality (locktime)
// - premature witness (in case segwit transactions are added to mempool before
//   segwit activation)
// - serialized size (in case -brickmaxsize is in use)
bool BrickAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package)
{
    uint64_t nPotentialBrickSize = nBrickSize; // only used with fNeedSizeAccounting
    BOOST_FOREACH (const CTxMemPool::txiter it, package) {
        if (!IsFinalTx(it->GetTx(), nHeight, nLockTimeCutoff))
            return false;
        if (!fIncludeWitness && !it->GetTx().wit.IsNull())
            return false;
        if (fNeedSizeAccounting) {
            uint64_t nTxSize = ::GetSerializeSize(it->GetTx(), SER_NETWORK, PROTOCOL_VERSION);
            if (nPotentialBrickSize + nTxSize >= nBrickMaxSize) {
                return false;
            }
            nPotentialBrickSize += nTxSize;
        }
    }
    return true;
}

bool BrickAssembler::TestForBrick(CTxMemPool::txiter iter)
{
    if (nBrickWeight + iter->GetTxWeight() >= nBrickMaxWeight) {
        // If the brick is so close to full that no more txs will fit
        // or if we've tried more than 50 times to fill remaining space
        // then flag that the brick is finished
        if (nBrickWeight >  nBrickMaxWeight - 400 || lastFewTxs > 50) {
             brickFinished = true;
             return false;
        }
        // Once we're within 4000 weight of a full brick, only look at 50 more txs
        // to try to fill the remaining space.
        if (nBrickWeight > nBrickMaxWeight - 4000) {
            lastFewTxs++;
        }
        return false;
    }

    if (fNeedSizeAccounting) {
        if (nBrickSize + ::GetSerializeSize(iter->GetTx(), SER_NETWORK, PROTOCOL_VERSION) >= nBrickMaxSize) {
            if (nBrickSize >  nBrickMaxSize - 100 || lastFewTxs > 50) {
                 brickFinished = true;
                 return false;
            }
            if (nBrickSize > nBrickMaxSize - 1000) {
                lastFewTxs++;
            }
            return false;
        }
    }

    if (nBrickSigOpsCost + iter->GetSigOpCost() >= MAX_BRICK_SIGOPS_COST) {
        // If the brick has room for no more sig ops then
        // flag that the brick is finished
        if (nBrickSigOpsCost > MAX_BRICK_SIGOPS_COST - 8) {
            brickFinished = true;
            return false;
        }
        // Otherwise attempt to find another tx with fewer sigops
        // to put in the brick.
        return false;
    }

    // Must check that lock times are still valid
    // This can be removed once MTP is always enforced
    // as long as reorgs keep the mempool consistent.
    if (!IsFinalTx(iter->GetTx(), nHeight, nLockTimeCutoff))
        return false;

    return true;
}

void BrickAssembler::AddToBrick(CTxMemPool::txiter iter)
{
    pbrick->vtx.push_back(iter->GetTx());
    pbricktemplate->vTxFees.push_back(iter->GetFee());
    pbricktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    if (fNeedSizeAccounting) {
        nBrickSize += ::GetSerializeSize(iter->GetTx(), SER_NETWORK, PROTOCOL_VERSION);
    }
    nBrickWeight += iter->GetTxWeight();
    ++nBrickTx;
    nBrickSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBrick.insert(iter);

    bool fPrintPriority = GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        double dPriority = iter->GetPriority(nHeight);
        CAmount dummy;
        mempool.ApplyDeltas(iter->GetTx().GetHash(), dPriority, dummy);
        LogPrintf("priority %.1f fee %s txid %s\n",
                  dPriority,
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

void BrickAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
        indexed_modified_transaction_set &mapModifiedTx)
{
    BOOST_FOREACH(const CTxMemPool::txiter it, alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in brick) into the modified set
        BOOST_FOREACH(CTxMemPool::txiter desc, descendants) {
            if (alreadyAdded.count(desc))
                continue;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                modEntry.nSigOpCostWithAncestors -= it->GetSigOpCost();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
}

// Skip entries in mapTx that are already in a brick or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the brick)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool BrickAssembler::SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx)
{
    assert (it != mempool.mapTx.end());
    if (mapModifiedTx.count(it) || inBrick.count(it) || failedTx.count(it))
        return true;
    return false;
}

void BrickAssembler::SortForBrick(const CTxMemPool::setEntries& package, CTxMemPool::txiter entry, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for brick inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for brick inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BrickAssembler::addPackageTxs()
{
    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the brick
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    UpdatePackagesForAdded(inBrick, mapModifiedTx);

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;
    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty())
    {
        // First try to find a new transaction in mapTx to evaluate.
        if (mi != mempool.mapTx.get<ancestor_score>().end() &&
                SkipMapTxEntry(mempool.mapTx.project<0>(mi), mapModifiedTx, failedTx)) {
            ++mi;
            continue;
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareModifiedEntry()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBrick, and mapModifiedTx shouldn't
        // contain anything that is inBrick.
        assert(!inBrick.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < ::minRelayTxFee.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool.CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // Package can be added. Sort the entries in a valid order.
        vector<CTxMemPool::txiter> sortedEntries;
        SortForBrick(ancestors, iter, sortedEntries);

        for (size_t i=0; i<sortedEntries.size(); ++i) {
            AddToBrick(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        // Update transactions that depend on each of these
        UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

void BrickAssembler::addPriorityTxs()
{
    // How much of the brick should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBrickPrioritySize = GetArg("-brickprioritysize", DEFAULT_BRICK_PRIORITY_SIZE);
    nBrickPrioritySize = std::min(nBrickMaxSize, nBrickPrioritySize);

    if (nBrickPrioritySize == 0) {
        return;
    }

    bool fSizeAccounting = fNeedSizeAccounting;
    fNeedSizeAccounting = true;

    // This vector will be sorted into a priority queue:
    vector<TxCoinAgePriority> vecPriority;
    TxCoinAgePriorityCompare pricomparer;
    std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash> waitPriMap;
    typedef std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash>::iterator waitPriIter;
    double actualPriority = -1;

    vecPriority.reserve(mempool.mapTx.size());
    for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
         mi != mempool.mapTx.end(); ++mi)
    {
        double dPriority = mi->GetPriority(nHeight);
        CAmount dummy;
        mempool.ApplyDeltas(mi->GetTx().GetHash(), dPriority, dummy);
        vecPriority.push_back(TxCoinAgePriority(dPriority, mi));
    }
    std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer);

    CTxMemPool::txiter iter;
    while (!vecPriority.empty() && !brickFinished) { // add a tx from priority queue to fill the brickprioritysize
        iter = vecPriority.front().second;
        actualPriority = vecPriority.front().first;
        std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
        vecPriority.pop_back();

        // If tx already in brick, skip
        if (inBrick.count(iter)) {
            assert(false); // shouldn't happen for priority txs
            continue;
        }

        // cannot accept witness transactions into a non-witness brick
        if (!fIncludeWitness && !iter->GetTx().wit.IsNull())
            continue;

        // If tx is dependent on other mempool txs which haven't yet been included
        // then put it in the waitSet
        if (isStillDependent(iter)) {
            waitPriMap.insert(std::make_pair(iter, actualPriority));
            continue;
        }

        // If this tx fits in the brick add it, otherwise keep looping
        if (TestForBrick(iter)) {
            AddToBrick(iter);

            // If now that this txs is added we've surpassed our desired priority size
            // or have dropped below the AllowFreeThreshold, then we're done adding priority txs
            if (nBrickSize >= nBrickPrioritySize || !AllowFree(actualPriority)) {
                break;
            }

            // This tx was successfully added, so
            // add transactions that depend on this one to the priority queue to try again
            BOOST_FOREACH(CTxMemPool::txiter child, mempool.GetMemPoolChildren(iter))
            {
                waitPriIter wpiter = waitPriMap.find(child);
                if (wpiter != waitPriMap.end()) {
                    vecPriority.push_back(TxCoinAgePriority(wpiter->second,child));
                    std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                    waitPriMap.erase(wpiter);
                }
            }
        }
    }
    fNeedSizeAccounting = fSizeAccounting;
}

void IncrementExtraNonce(CBrick* pbrick, const CBrickIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBrick;
    if (hashPrevBrick != pbrick->hashPrevBrick)
    {
        nExtraNonce = 0;
        hashPrevBrick = pbrick->hashPrevBrick;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for brick.version=2
    CMutableTransaction txCoinbase(pbrick->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pbrick->vtx[0] = txCoinbase;
    pbrick->hashMerkleRoot = BrickMerkleRoot(*pbrick);
}
