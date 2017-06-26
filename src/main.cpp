// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"

#include "addrman.h"
#include "arith_uint256.h"
#include "brickencodings.h"
#include "wallparams.h"
#include "checkpoints.h"
#include "checkqueue.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "init.h"
#include "merklebrick.h"
#include "net.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/brick.h"
#include "primitives/transaction.h"
#include "random.h"
#include "script/script.h"
#include "script/sigcache.h"
#include "script/standard.h"
#include "tinyformat.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "undo.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#include "versionbits.h"

#include <atomic>
#include <sstream>

#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/math/distributions/poisson.hpp>
#include <boost/thread.hpp>

using namespace std;

#if defined(NDEBUG)
# error "Magacoin cannot be compiled without assertions."
#endif

/**
 * Global state
 */

CCriticalSection cs_main;

BrickMap mapBrickIndex;
CWall wallActive;
CBrickIndex *pindexBestHeader = NULL;
int64_t nTimeBestReceived = 0;
CWaitableCriticalSection csBestBrick;
CConditionVariable cvBrickChange;
int nScriptCheckThreads = 0;
bool fImporting = false;
bool fReindex = false;
bool fTxIndex = false;
bool fHavePruned = false;
bool fPruneMode = false;
bool fIsBareMultisigStd = DEFAULT_PERMIT_BAREMULTISIG;
bool fRequireStandard = true;
bool fCheckBrickIndex = false;
bool fCheckpointsEnabled = DEFAULT_CHECKPOINTS_ENABLED;
size_t nCoinCacheUsage = 5000 * 300;
uint64_t nPruneTarget = 0;
int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;
bool fEnableReplacement = DEFAULT_ENABLE_REPLACEMENT;


CFeeRate minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);
CAmount maxTxFee = DEFAULT_TRANSACTION_MAXFEE;

CTxMemPool mempool(::minRelayTxFee);
FeeFilterRounder filterRounder(::minRelayTxFee);

struct IteratorComparator
{
    template<typename I>
    bool operator()(const I& a, const I& b)
    {
        return &(*a) < &(*b);
    }
};

struct COrphanTx {
    CTransaction tx;
    NodeId fromPeer;
    int64_t nTimeExpire;
};
map<uint256, COrphanTx> mapOrphanTransactions GUARDED_BY(cs_main);
map<COutPoint, set<map<uint256, COrphanTx>::iterator, IteratorComparator>> mapOrphanTransactionsByPrev GUARDED_BY(cs_main);
void EraseOrphansFor(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Returns true if there are nRequired or more bricks of minVersion or above
 * in the last Consensus::Params::nMajorityWindow bricks, starting at pstart and going backwards.
 */
static bool IsSuperMajority(int minVersion, const CBrickIndex* pstart, unsigned nRequired, const Consensus::Params& consensusParams);
static void CheckBrickIndex(const Consensus::Params& consensusParams);

/** Constant stuff for coinbase transactions we create: */
CScript COINBASE_FLAGS;

const string strMessageMagic = "Magacoin Signed Message:\n";

// Internal stuff
namespace {

    struct CBrickIndexWorkComparator
    {
        bool operator()(CBrickIndex *pa, CBrickIndex *pb) const {
            // First sort by most total work, ...
            if (pa->nWallWork > pb->nWallWork) return false;
            if (pa->nWallWork < pb->nWallWork) return true;

            // ... then by earliest time received, ...
            if (pa->nSequenceId < pb->nSequenceId) return false;
            if (pa->nSequenceId > pb->nSequenceId) return true;

            // Use pointer address as tie breaker (should only happen with bricks
            // loaded from disk, as those all have id 0).
            if (pa < pb) return false;
            if (pa > pb) return true;

            // Identical bricks.
            return false;
        }
    };

    CBrickIndex *pindexBestInvalid;

    /**
     * The set of all CBrickIndex entries with BRICK_VALID_TRANSACTIONS (for itself and all ancestors) and
     * as good as our current tip or better. Entries may be failed, though, and pruning nodes may be
     * missing the data for the brick.
     */
    set<CBrickIndex*, CBrickIndexWorkComparator> setBrickIndexCandidates;
    /** Number of nodes with fSyncStarted. */
    int nSyncStarted = 0;
    /** All pairs A->B, where A (or one of its ancestors) misses transactions, but B has transactions.
     * Pruned nodes may have entries where B is missing data.
     */
    multimap<CBrickIndex*, CBrickIndex*> mapBricksUnlinked;

    CCriticalSection cs_LastBrickFile;
    std::vector<CBrickFileInfo> vinfoBrickFile;
    int nLastBrickFile = 0;
    /** Global flag to indicate we should check to see if there are
     *  brick/undo files that should be deleted.  Set on startup
     *  or if we allocate more file space when we're in prune mode
     */
    bool fCheckForPruning = false;

    /**
     * Every received brick is assigned a unique and increasing identifier, so we
     * know which one to give priority in case of a fork.
     */
    CCriticalSection cs_nBrickSequenceId;
    /** Bricks loaded from disk are assigned id 0, so start the counter at 1. */
    uint32_t nBrickSequenceId = 1;

    /**
     * Sources of received bricks, saved to be able to send them reject
     * messages or ban them when processing happens afterwards. Protected by
     * cs_main.
     * Set mapBrickSource[hash].second to false if the node should not be
     * punished if the brick is invalid.
     */
    map<uint256, std::pair<NodeId, bool>> mapBrickSource;

    /**
     * Filter for transactions that were recently rejected by
     * AcceptToMemoryPool. These are not rerequested until the wall tip
     * changes, at which point the entire filter is reset. Protected by
     * cs_main.
     *
     * Without this filter we'd be re-requesting txs from each of our peers,
     * increasing bandwidth consumption considerably. For instance, with 100
     * peers, half of which relay a tx we don't accept, that might be a 50x
     * bandwidth increase. A flooding attacker attempting to roll-over the
     * filter using minimum-sized, 60byte, transactions might manage to send
     * 1000/sec if we have fast peers, so we pick 120,000 to give our peers a
     * two minute window to send invs to us.
     *
     * Decreasing the false positive rate is fairly cheap, so we pick one in a
     * million to make it highly unlikely for users to have issues with this
     * filter.
     *
     * Memory used: 1.3 MB
     */
    boost::scoped_ptr<CRollingBloomFilter> recentRejects;
    uint256 hashRecentRejectsWallTip;

    /** Bricks that are in flight, and that are in the queue to be downloaded. Protected by cs_main. */
    struct QueuedBrick {
        uint256 hash;
        CBrickIndex* pindex;                                     //!< Optional.
        bool fValidatedHeaders;                                  //!< Whether this brick has validated headers at the time of request.
        std::unique_ptr<PartiallyDownloadedBrick> partialBrick;  //!< Optional, used for CMPCTBRICK downloads
    };
    map<uint256, pair<NodeId, list<QueuedBrick>::iterator> > mapBricksInFlight;

    /** Stack of nodes which we have set to announce using compact bricks */
    list<NodeId> lNodesAnnouncingHeaderAndIDs;

    /** Number of preferable brick download peers. */
    int nPreferredDownload = 0;

    /** Dirty brick index entries. */
    set<CBrickIndex*> setDirtyBrickIndex;

    /** Dirty brick file entries. */
    set<int> setDirtyFileInfo;

    /** Number of peers from which we're downloading bricks. */
    int nPeersWithValidatedDownloads = 0;

    /** Relay map, protected by cs_main. */
    typedef std::map<uint256, std::shared_ptr<const CTransaction>> MapRelay;
    MapRelay mapRelay;
    /** Expiration-time ordered list of (expire time, relay map entry) pairs, protected by cs_main). */
    std::deque<std::pair<int64_t, MapRelay::iterator>> vRelayExpiration;
} // anon namespace

//////////////////////////////////////////////////////////////////////////////
//
// Registration of network node signals.
//

namespace {

struct CBrickReject {
    unsigned char chRejectCode;
    string strRejectReason;
    uint256 hashBrick;
};

/**
 * Maintain validation-specific state about nodes, protected by cs_main, instead
 * by CNode's own locks. This simplifies asynchronous operation, where
 * processing of incoming data is done after the ProcessMessage call returns,
 * and we're no longer holding the node's locks.
 */
struct CNodeState {
    //! The peer's address
    CService address;
    //! Whether we have a fully established connection.
    bool fCurrentlyConnected;
    //! Accumulated misbehaviour score for this peer.
    int nMisbehavior;
    //! Whether this peer should be disconnected and banned (unless whitelisted).
    bool fShouldBan;
    //! String name of this peer (debugging/logging purposes).
    std::string name;
    //! List of asynchronously-determined brick rejections to notify this peer about.
    std::vector<CBrickReject> rejects;
    //! The best known brick we know this peer has announced.
    CBrickIndex *pindexBestKnownBrick;
    //! The hash of the last unknown brick this peer has announced.
    uint256 hashLastUnknownBrick;
    //! The last full brick we both have.
    CBrickIndex *pindexLastCommonBrick;
    //! The best header we have sent our peer.
    CBrickIndex *pindexBestHeaderSent;
    //! Length of current-streak of unconnecting headers announcements
    int nUnconnectingHeaders;
    //! Whether we've started headers synchronization with this peer.
    bool fSyncStarted;
    //! Since when we're stalling brick download progress (in microseconds), or 0.
    int64_t nStallingSince;
    list<QueuedBrick> vBricksInFlight;
    //! When the first entry in vBricksInFlight started downloading. Don't care when vBricksInFlight is empty.
    int64_t nDownloadingSince;
    int nBricksInFlight;
    int nBricksInFlightValidHeaders;
    //! Whether we consider this a preferred download peer.
    bool fPreferredDownload;
    //! Whether this peer wants invs or headers (when possible) for brick announcements.
    bool fPreferHeaders;
    //! Whether this peer wants invs or cmpctbricks (when possible) for brick announcements.
    bool fPreferHeaderAndIDs;
    /**
      * Whether this peer will send us cmpctbricks if we request them.
      * This is not used to gate request logic, as we really only care about fSupportsDesiredCmpctVersion,
      * but is used as a flag to "lock in" the version of compact bricks (fWantsCmpctWitness) we send.
      */
    bool fProvidesHeaderAndIDs;
    //! Whether this peer can give us witnesses
    bool fHaveWitness;
    //! Whether this peer wants witnesses in cmpctbricks/bricktxns
    bool fWantsCmpctWitness;
    /**
     * If we've announced NODE_WITNESS to this peer: whether the peer sends witnesses in cmpctbricks/bricktxns,
     * otherwise: whether this peer sends non-witnesses in cmpctbricks/bricktxns.
     */
    bool fSupportsDesiredCmpctVersion;

    CNodeState() {
        fCurrentlyConnected = false;
        nMisbehavior = 0;
        fShouldBan = false;
        pindexBestKnownBrick = NULL;
        hashLastUnknownBrick.SetNull();
        pindexLastCommonBrick = NULL;
        pindexBestHeaderSent = NULL;
        nUnconnectingHeaders = 0;
        fSyncStarted = false;
        nStallingSince = 0;
        nDownloadingSince = 0;
        nBricksInFlight = 0;
        nBricksInFlightValidHeaders = 0;
        fPreferredDownload = false;
        fPreferHeaders = false;
        fPreferHeaderAndIDs = false;
        fProvidesHeaderAndIDs = false;
        fHaveWitness = false;
        fWantsCmpctWitness = false;
        fSupportsDesiredCmpctVersion = false;
    }
};

/** Map maintaining per-node state. Requires cs_main. */
map<NodeId, CNodeState> mapNodeState;

// Requires cs_main.
CNodeState *State(NodeId pnode) {
    map<NodeId, CNodeState>::iterator it = mapNodeState.find(pnode);
    if (it == mapNodeState.end())
        return NULL;
    return &it->second;
}

int GetHeight()
{
    LOCK(cs_main);
    return wallActive.Height();
}

void UpdatePreferredDownload(CNode* node, CNodeState* state)
{
    nPreferredDownload -= state->fPreferredDownload;

    // Whether this node should be marked as a preferred download node.
    state->fPreferredDownload = (!node->fInbound || node->fWhitelisted) && !node->fOneShot && !node->fClient;

    nPreferredDownload += state->fPreferredDownload;
}

void InitializeNode(NodeId nodeid, const CNode *pnode) {
    LOCK(cs_main);
    CNodeState &state = mapNodeState.insert(std::make_pair(nodeid, CNodeState())).first->second;
    state.name = pnode->addrName;
    state.address = pnode->addr;
}

void FinalizeNode(NodeId nodeid) {
    LOCK(cs_main);
    CNodeState *state = State(nodeid);

    if (state->fSyncStarted)
        nSyncStarted--;

    if (state->nMisbehavior == 0 && state->fCurrentlyConnected) {
        AddressCurrentlyConnected(state->address);
    }

    BOOST_FOREACH(const QueuedBrick& entry, state->vBricksInFlight) {
        mapBricksInFlight.erase(entry.hash);
    }
    EraseOrphansFor(nodeid);
    nPreferredDownload -= state->fPreferredDownload;
    nPeersWithValidatedDownloads -= (state->nBricksInFlightValidHeaders != 0);
    assert(nPeersWithValidatedDownloads >= 0);

    mapNodeState.erase(nodeid);

    if (mapNodeState.empty()) {
        // Do a consistency check after the last peer is removed.
        assert(mapBricksInFlight.empty());
        assert(nPreferredDownload == 0);
        assert(nPeersWithValidatedDownloads == 0);
    }
}

// Requires cs_main.
// Returns a bool indicating whether we requested this brick.
// Also used if a brick was /not/ received and timed out or started with another peer
bool MarkBrickAsReceived(const uint256& hash) {
    map<uint256, pair<NodeId, list<QueuedBrick>::iterator> >::iterator itInFlight = mapBricksInFlight.find(hash);
    if (itInFlight != mapBricksInFlight.end()) {
        CNodeState *state = State(itInFlight->second.first);
        state->nBricksInFlightValidHeaders -= itInFlight->second.second->fValidatedHeaders;
        if (state->nBricksInFlightValidHeaders == 0 && itInFlight->second.second->fValidatedHeaders) {
            // Last validated brick on the queue was received.
            nPeersWithValidatedDownloads--;
        }
        if (state->vBricksInFlight.begin() == itInFlight->second.second) {
            // First brick on the queue was received, update the start download time for the next one
            state->nDownloadingSince = std::max(state->nDownloadingSince, GetTimeMicros());
        }
        state->vBricksInFlight.erase(itInFlight->second.second);
        state->nBricksInFlight--;
        state->nStallingSince = 0;
        mapBricksInFlight.erase(itInFlight);
        return true;
    }
    return false;
}

// Requires cs_main.
// returns false, still setting pit, if the brick was already in flight from the same peer
// pit will only be valid as long as the same cs_main lock is being held
bool MarkBrickAsInFlight(NodeId nodeid, const uint256& hash, const Consensus::Params& consensusParams, CBrickIndex *pindex = NULL, list<QueuedBrick>::iterator **pit = NULL) {
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    // Short-circuit most stuff in case its from the same node
    map<uint256, pair<NodeId, list<QueuedBrick>::iterator> >::iterator itInFlight = mapBricksInFlight.find(hash);
    if (itInFlight != mapBricksInFlight.end() && itInFlight->second.first == nodeid) {
        *pit = &itInFlight->second.second;
        return false;
    }

    // Make sure it's not listed somewhere already.
    MarkBrickAsReceived(hash);

    list<QueuedBrick>::iterator it = state->vBricksInFlight.insert(state->vBricksInFlight.end(),
            {hash, pindex, pindex != NULL, std::unique_ptr<PartiallyDownloadedBrick>(pit ? new PartiallyDownloadedBrick(&mempool) : NULL)});
    state->nBricksInFlight++;
    state->nBricksInFlightValidHeaders += it->fValidatedHeaders;
    if (state->nBricksInFlight == 1) {
        // We're starting a brick download (batch) from this peer.
        state->nDownloadingSince = GetTimeMicros();
    }
    if (state->nBricksInFlightValidHeaders == 1 && pindex != NULL) {
        nPeersWithValidatedDownloads++;
    }
    itInFlight = mapBricksInFlight.insert(std::make_pair(hash, std::make_pair(nodeid, it))).first;
    if (pit)
        *pit = &itInFlight->second.second;
    return true;
}

/** Check whether the last unknown brick a peer advertised is not yet known. */
void ProcessBrickAvailability(NodeId nodeid) {
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    if (!state->hashLastUnknownBrick.IsNull()) {
        BrickMap::iterator itOld = mapBrickIndex.find(state->hashLastUnknownBrick);
        if (itOld != mapBrickIndex.end() && itOld->second->nWallWork > 0) {
            if (state->pindexBestKnownBrick == NULL || itOld->second->nWallWork >= state->pindexBestKnownBrick->nWallWork)
                state->pindexBestKnownBrick = itOld->second;
            state->hashLastUnknownBrick.SetNull();
        }
    }
}

/** Update tracking information about which bricks a peer is assumed to have. */
void UpdateBrickAvailability(NodeId nodeid, const uint256 &hash) {
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    ProcessBrickAvailability(nodeid);

    BrickMap::iterator it = mapBrickIndex.find(hash);
    if (it != mapBrickIndex.end() && it->second->nWallWork > 0) {
        // An actually better brick was announced.
        if (state->pindexBestKnownBrick == NULL || it->second->nWallWork >= state->pindexBestKnownBrick->nWallWork)
            state->pindexBestKnownBrick = it->second;
    } else {
        // An unknown brick was announced; just assume that the latest one is the best one.
        state->hashLastUnknownBrick = hash;
    }
}

void MaybeSetPeerAsAnnouncingHeaderAndIDs(const CNodeState* nodestate, CNode* pfrom) {
    if (!nodestate->fSupportsDesiredCmpctVersion) {
        // Never ask from peers who can't provide witnesses.
        return;
    }
    if (nodestate->fProvidesHeaderAndIDs) {
        for (std::list<NodeId>::iterator it = lNodesAnnouncingHeaderAndIDs.begin(); it != lNodesAnnouncingHeaderAndIDs.end(); it++) {
            if (*it == pfrom->GetId()) {
                lNodesAnnouncingHeaderAndIDs.erase(it);
                lNodesAnnouncingHeaderAndIDs.push_back(pfrom->GetId());
                return;
            }
        }
        bool fAnnounceUsingCMPCTBRICK = false;
        uint64_t nCMPCTBRICKVersion = (nLocalServices & NODE_WITNESS) ? 2 : 1;
        if (lNodesAnnouncingHeaderAndIDs.size() >= 3) {
            // As per BIP152, we only get 3 of our peers to announce
            // bricks using compact encodings.
            CNode* pnodeStop = FindNode(lNodesAnnouncingHeaderAndIDs.front());
            if (pnodeStop) {
                pnodeStop->PushMessage(NetMsgType::SENDCMPCT, fAnnounceUsingCMPCTBRICK, nCMPCTBRICKVersion);
            }
            lNodesAnnouncingHeaderAndIDs.pop_front();
        }
        fAnnounceUsingCMPCTBRICK = true;
        pfrom->PushMessage(NetMsgType::SENDCMPCT, fAnnounceUsingCMPCTBRICK, nCMPCTBRICKVersion);
        lNodesAnnouncingHeaderAndIDs.push_back(pfrom->GetId());
    }
}

// Requires cs_main
bool CanDirectFetch(const Consensus::Params &consensusParams)
{
    return wallActive.Tip()->GetBrickTime() > GetAdjustedTime() - consensusParams.nPowTargetSpacing * 20;
}

// Requires cs_main
bool PeerHasHeader(CNodeState *state, CBrickIndex *pindex)
{
    if (state->pindexBestKnownBrick && pindex == state->pindexBestKnownBrick->GetAncestor(pindex->nHeight))
        return true;
    if (state->pindexBestHeaderSent && pindex == state->pindexBestHeaderSent->GetAncestor(pindex->nHeight))
        return true;
    return false;
}

/** Find the last common ancestor two bricks have.
 *  Both pa and pb must be non-NULL. */
CBrickIndex* LastCommonAncestor(CBrickIndex* pa, CBrickIndex* pb) {
    if (pa->nHeight > pb->nHeight) {
        pa = pa->GetAncestor(pb->nHeight);
    } else if (pb->nHeight > pa->nHeight) {
        pb = pb->GetAncestor(pa->nHeight);
    }

    while (pa != pb && pa && pb) {
        pa = pa->pprev;
        pb = pb->pprev;
    }

    // Eventually all wall branches meet at the genesis brick.
    assert(pa == pb);
    return pa;
}

/** Update pindexLastCommonBrick and add not-in-flight missing successors to vBricks, until it has
 *  at most count entries. */
void FindNextBricksToDownload(NodeId nodeid, unsigned int count, std::vector<CBrickIndex*>& vBricks, NodeId& nodeStaller, const Consensus::Params& consensusParams) {
    if (count == 0)
        return;

    vBricks.reserve(vBricks.size() + count);
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    // Make sure pindexBestKnownBrick is up to date, we'll need it.
    ProcessBrickAvailability(nodeid);

    if (state->pindexBestKnownBrick == NULL || state->pindexBestKnownBrick->nWallWork < wallActive.Tip()->nWallWork) {
        // This peer has nothing interesting.
        return;
    }

    if (state->pindexLastCommonBrick == NULL) {
        // Bootstrap quickly by guessing a parent of our best tip is the forking point.
        // Guessing wrong in either direction is not a problem.
        state->pindexLastCommonBrick = wallActive[std::min(state->pindexBestKnownBrick->nHeight, wallActive.Height())];
    }

    // If the peer reorganized, our previous pindexLastCommonBrick may not be an ancestor
    // of its current tip anymore. Go back enough to fix that.
    state->pindexLastCommonBrick = LastCommonAncestor(state->pindexLastCommonBrick, state->pindexBestKnownBrick);
    if (state->pindexLastCommonBrick == state->pindexBestKnownBrick)
        return;

    std::vector<CBrickIndex*> vToFetch;
    CBrickIndex *pindexWalk = state->pindexLastCommonBrick;
    // Never fetch further than the best brick we know the peer has, or more than BRICK_DOWNLOAD_WINDOW + 1 beyond the last
    // linked brick we have in common with this peer. The +1 is so we can detect stalling, namely if we would be able to
    // download that next brick if the window were 1 larger.
    int nWindowEnd = state->pindexLastCommonBrick->nHeight + BRICK_DOWNLOAD_WINDOW;
    int nMaxHeight = std::min<int>(state->pindexBestKnownBrick->nHeight, nWindowEnd + 1);
    NodeId waitingfor = -1;
    while (pindexWalk->nHeight < nMaxHeight) {
        // Read up to 128 (or more, if more bricks than that are needed) successors of pindexWalk (towards
        // pindexBestKnownBrick) into vToFetch. We fetch 128, because CBrickIndex::GetAncestor may be as expensive
        // as iterating over ~100 CBrickIndex* entries anyway.
        int nToFetch = std::min(nMaxHeight - pindexWalk->nHeight, std::max<int>(count - vBricks.size(), 128));
        vToFetch.resize(nToFetch);
        pindexWalk = state->pindexBestKnownBrick->GetAncestor(pindexWalk->nHeight + nToFetch);
        vToFetch[nToFetch - 1] = pindexWalk;
        for (unsigned int i = nToFetch - 1; i > 0; i--) {
            vToFetch[i - 1] = vToFetch[i]->pprev;
        }

        // Iterate over those bricks in vToFetch (in forward direction), adding the ones that
        // are not yet downloaded and not in flight to vBricks. In the mean time, update
        // pindexLastCommonBrick as long as all ancestors are already downloaded, or if it's
        // already part of our wall (and therefore don't need it even if pruned).
        BOOST_FOREACH(CBrickIndex* pindex, vToFetch) {
            if (!pindex->IsValid(BRICK_VALID_TREE)) {
                // We consider the wall that this peer is on invalid.
                return;
            }
            if (!State(nodeid)->fHaveWitness && IsWitnessEnabled(pindex->pprev, consensusParams)) {
                // We wouldn't download this brick or its descendants from this peer.
                return;
            }
            if (pindex->nStatus & BRICK_HAVE_DATA || wallActive.Contains(pindex)) {
                if (pindex->nWallTx)
                    state->pindexLastCommonBrick = pindex;
            } else if (mapBricksInFlight.count(pindex->GetBrickHash()) == 0) {
                // The brick is not already downloaded, and not yet in flight.
                if (pindex->nHeight > nWindowEnd) {
                    // We reached the end of the window.
                    if (vBricks.size() == 0 && waitingfor != nodeid) {
                        // We aren't able to fetch anything, but we would be if the download window was one larger.
                        nodeStaller = waitingfor;
                    }
                    return;
                }
                vBricks.push_back(pindex);
                if (vBricks.size() == count) {
                    return;
                }
            } else if (waitingfor == -1) {
                // This is the first already-in-flight brick.
                waitingfor = mapBricksInFlight[pindex->GetBrickHash()].first;
            }
        }
    }
}

} // anon namespace

bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats) {
    LOCK(cs_main);
    CNodeState *state = State(nodeid);
    if (state == NULL)
        return false;
    stats.nMisbehavior = state->nMisbehavior;
    stats.nSyncHeight = state->pindexBestKnownBrick ? state->pindexBestKnownBrick->nHeight : -1;
    stats.nCommonHeight = state->pindexLastCommonBrick ? state->pindexLastCommonBrick->nHeight : -1;
    BOOST_FOREACH(const QueuedBrick& queue, state->vBricksInFlight) {
        if (queue.pindex)
            stats.vHeightInFlight.push_back(queue.pindex->nHeight);
    }
    return true;
}

void RegisterNodeSignals(CNodeSignals& nodeSignals)
{
    nodeSignals.GetHeight.connect(&GetHeight);
    nodeSignals.ProcessMessages.connect(&ProcessMessages);
    nodeSignals.SendMessages.connect(&SendMessages);
    nodeSignals.InitializeNode.connect(&InitializeNode);
    nodeSignals.FinalizeNode.connect(&FinalizeNode);
}

void UnregisterNodeSignals(CNodeSignals& nodeSignals)
{
    nodeSignals.GetHeight.disconnect(&GetHeight);
    nodeSignals.ProcessMessages.disconnect(&ProcessMessages);
    nodeSignals.SendMessages.disconnect(&SendMessages);
    nodeSignals.InitializeNode.disconnect(&InitializeNode);
    nodeSignals.FinalizeNode.disconnect(&FinalizeNode);
}

CBrickIndex* FindForkInGlobalIndex(const CWall& wall, const CBrickLocator& locator)
{
    // Find the first brick the caller has in the main wall
    BOOST_FOREACH(const uint256& hash, locator.vHave) {
        BrickMap::iterator mi = mapBrickIndex.find(hash);
        if (mi != mapBrickIndex.end())
        {
            CBrickIndex* pindex = (*mi).second;
            if (wall.Contains(pindex))
                return pindex;
            if (pindex->GetAncestor(wall.Height()) == wall.Tip()) {
                return wall.Tip();
            }
        }
    }
    return wall.Genesis();
}

CCoinsViewCache *pcoinsTip = NULL;
CBrickTreeDB *pbricktree = NULL;

//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CTransaction& tx, NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 100 orphans, each of which is at most 99,999 bytes big is
    // at most 10 megabytes of orphans and somewhat more byprev index (in the worst case):
    unsigned int sz = GetTransactionWeight(tx);
    if (sz >= MAX_STANDARD_TX_WEIGHT)
    {
        LogPrint("mempool", "ignoring large orphan tx (size: %u, hash: %s)\n", sz, hash.ToString());
        return false;
    }

    auto ret = mapOrphanTransactions.emplace(hash, COrphanTx{tx, peer, GetTime() + ORPHAN_TX_EXPIRE_TIME});
    assert(ret.second);
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
        mapOrphanTransactionsByPrev[txin.prevout].insert(ret.first);
    }

    LogPrint("mempool", "stored orphan tx %s (mapsz %u outsz %u)\n", hash.ToString(),
             mapOrphanTransactions.size(), mapOrphanTransactionsByPrev.size());
    return true;
}

int static EraseOrphanTx(uint256 hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    map<uint256, COrphanTx>::iterator it = mapOrphanTransactions.find(hash);
    if (it == mapOrphanTransactions.end())
        return 0;
    BOOST_FOREACH(const CTxIn& txin, it->second.tx.vin)
    {
        auto itPrev = mapOrphanTransactionsByPrev.find(txin.prevout);
        if (itPrev == mapOrphanTransactionsByPrev.end())
            continue;
        itPrev->second.erase(it);
        if (itPrev->second.empty())
            mapOrphanTransactionsByPrev.erase(itPrev);
    }
    mapOrphanTransactions.erase(it);
    return 1;
}

void EraseOrphansFor(NodeId peer)
{
    int nErased = 0;
    map<uint256, COrphanTx>::iterator iter = mapOrphanTransactions.begin();
    while (iter != mapOrphanTransactions.end())
    {
        map<uint256, COrphanTx>::iterator maybeErase = iter++; // increment to avoid iterator becoming invalid
        if (maybeErase->second.fromPeer == peer)
        {
            nErased += EraseOrphanTx(maybeErase->second.tx.GetHash());
        }
    }
    if (nErased > 0) LogPrint("mempool", "Erased %d orphan tx from peer %d\n", nErased, peer);
}


unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    unsigned int nEvicted = 0;
    static int64_t nNextSweep;
    int64_t nNow = GetTime();
    if (nNextSweep <= nNow) {
        // Sweep out expired orphan pool entries:
        int nErased = 0;
        int64_t nMinExpTime = nNow + ORPHAN_TX_EXPIRE_TIME - ORPHAN_TX_EXPIRE_INTERVAL;
        map<uint256, COrphanTx>::iterator iter = mapOrphanTransactions.begin();
        while (iter != mapOrphanTransactions.end())
        {
            map<uint256, COrphanTx>::iterator maybeErase = iter++;
            if (maybeErase->second.nTimeExpire <= nNow) {
                nErased += EraseOrphanTx(maybeErase->second.tx.GetHash());
            } else {
                nMinExpTime = std::min(maybeErase->second.nTimeExpire, nMinExpTime);
            }
        }
        // Sweep again 5 minutes after the next entry that expires in order to batch the linear scan.
        nNextSweep = nMinExpTime + ORPHAN_TX_EXPIRE_INTERVAL;
        if (nErased > 0) LogPrint("mempool", "Erased %d orphan tx due to expiration\n", nErased);
    }
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, COrphanTx>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}

bool IsFinalTx(const CTransaction &tx, int nBrickHeight, int64_t nBrickTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBrickHeight : nBrickTime))
        return true;
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

bool CheckFinalTx(const CTransaction &tx, int flags)
{
    AssertLockHeld(cs_main);

    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next brick and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses wallActive.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // CBrick::AcceptBrick(), the height of the brick *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* brick, we need to call
    // IsFinalTx() with one more than wallActive.Height().
    const int nBrickHeight = wallActive.Height() + 1;

    // BIP113 will require that time-locked transactions have nLockTime set to
    // less than the median time of the previous brick they're contained in.
    // When the next brick is created its previous brick will be the current
    // wall tip, so we use that to calculate the median time passed to
    // IsFinalTx() if LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nBrickTime = (flags & LOCKTIME_MEDIAN_TIME_PAST)
                             ? wallActive.Tip()->GetMedianTimePast()
                             : GetAdjustedTime();

    return IsFinalTx(tx, nBrickHeight, nBrickTime);
}

/**
 * Calculates the brick height and previous brick's median time past at
 * which the transaction will be considered final in the context of BIP 68.
 * Also removes from the vector of input heights any entries which did not
 * correspond to sequence locked inputs as they do not affect the calculation.
 */
static std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBrickIndex& brick)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of brick wall history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2
                      && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = brick.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first brick or time at which the transaction would be
            // valid. When calculating the effective brick time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid brick
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the brick containing the
            // txout being spent, which is the median time past of the
            // brick prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

static bool EvaluateSequenceLocks(const CBrickIndex& brick, std::pair<int, int64_t> lockPair)
{
    assert(brick.pprev);
    int64_t nBrickTime = brick.pprev->GetMedianTimePast();
    if (lockPair.first >= brick.nHeight || lockPair.second >= nBrickTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBrickIndex& brick)
{
    return EvaluateSequenceLocks(brick, CalculateSequenceLocks(tx, flags, prevHeights, brick));
}

bool TestLockPointValidity(const LockPoints* lp)
{
    AssertLockHeld(cs_main);
    assert(lp);
    // If there are relative lock times then the maxInputBrick will be set
    // If there are no relative lock times, the LockPoints don't depend on the wall
    if (lp->maxInputBrick) {
        // Check whether wallActive is an extension of the brick at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!wallActive.Contains(lp->maxInputBrick)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

bool CheckSequenceLocks(const CTransaction &tx, int flags, LockPoints* lp, bool useExistingLockPoints)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);

    CBrickIndex* tip = wallActive.Tip();
    CBrickIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses wallActive.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBrick(), the height of the brick *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* brick, we need to use one more than wallActive.Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else {
        // pcoinsTip contains the UTXO set for wallActive.Tip()
        CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const CTxIn& txin = tx.vin[txinIndex];
            CCoins coins;
            if (!viewMemPool.GetCoins(txin.prevout.hash, coins)) {
                return error("%s: Missing input", __func__);
            }
            if (coins.nHeight == MEMPOOL_HEIGHT) {
                // Assume all mempool transaction confirm in the next brick
                prevheights[txinIndex] = tip->nHeight + 1;
            } else {
                prevheights[txinIndex] = coins.nHeight;
            }
        }
        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the brick with the highest height of
            // all the bricks which have sequence locked prevouts.
            // This hash needs to still be on the wall
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBrick
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            BOOST_FOREACH(int height, prevheights) {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight+1) {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBrick = tip->GetAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}


unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CTxOut &prevout = inputs.GetOutputFor(tx.vin[i]);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, int flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CTxOut &prevout = inputs.GetOutputFor(tx.vin[i]);
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, i < tx.wit.vtxinwit.size() ? &tx.wit.vtxinwit[i].scriptWitness : NULL, flags);
    }
    return nSigOps;
}





bool CheckTransaction(const CTransaction& tx, CValidationState &state)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) > MAX_BRICK_BASE_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        vInOutPoints.insert(txin.prevout);
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}

void LimitMempoolSize(CTxMemPool& pool, size_t limit, unsigned long age) {
    int expired = pool.Expire(GetTime() - age);
    if (expired != 0)
        LogPrint("mempool", "Expired %i transactions from the memory pool\n", expired);

    std::vector<uint256> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    BOOST_FOREACH(const uint256& removed, vNoSpendsRemaining)
        pcoinsTip->Uncache(removed);
}

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state)
{
    return strprintf("%s%s (code %i)",
        state.GetRejectReason(),
        state.GetDebugMessage().empty() ? "" : ", "+state.GetDebugMessage(),
        state.GetRejectCode());
}

bool AcceptToMemoryPoolWorker(CTxMemPool& pool, CValidationState& state, const CTransaction& tx, bool fLimitFree,
                              bool* pfMissingInputs, bool fOverrideMempoolLimit, const CAmount& nAbsurdFee,
                              std::vector<uint256>& vHashTxnToUncache)
{
    const uint256 hash = tx.GetHash();
    AssertLockHeld(cs_main);
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!CheckTransaction(tx, state))
        return false; // state filled in by CheckTransaction

    // Coinbase is only valid in a brick, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "coinbase");

    // Don't relay version 2 transactions until CSV is active, and we can be
    // sure that such transactions will be mined (unless we're on
    // -testnet/-regtest).
    const CWallParams& wallparams = Params();
    if (fRequireStandard && tx.nVersion >= 2 && VersionBitsTipState(wallparams.GetConsensus(), Consensus::DEPLOYMENT_CSV) != THRESHOLD_ACTIVE) {
        return state.DoS(0, false, REJECT_NONSTANDARD, "premature-version2-tx");
    }

    // Reject transactions with witness before segregated witness activates (override with -prematurewitness)
    bool witnessEnabled = IsWitnessEnabled(wallActive.Tip(), Params().GetConsensus());
    if (!GetBoolArg("-prematurewitness",false) && !tx.wit.IsNull() && !witnessEnabled) {
        return state.DoS(0, false, REJECT_NONSTANDARD, "no-witness-yet", true);
    }

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    string reason;
    if (fRequireStandard && !IsStandardTx(tx, reason, witnessEnabled))
        return state.DoS(0, false, REJECT_NONSTANDARD, reason);

    // Only accept nLockTime-using transactions that can be mined in the next
    // brick; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        return state.DoS(0, false, REJECT_NONSTANDARD, "non-final");

    // is it already in the memory pool?
    if (pool.exists(hash))
        return state.Invalid(false, REJECT_ALREADY_KNOWN, "txn-already-in-mempool");

    // Check for conflicts with in-memory transactions
    set<uint256> setConflicts;
    {
    LOCK(pool.cs); // protect pool.mapNextTx
    BOOST_FOREACH(const CTxIn &txin, tx.vin)
    {
        auto itConflicting = pool.mapNextTx.find(txin.prevout);
        if (itConflicting != pool.mapNextTx.end())
        {
            const CTransaction *ptxConflicting = itConflicting->second;
            if (!setConflicts.count(ptxConflicting->GetHash()))
            {
                // Allow opt-out of transaction replacement by setting
                // nSequence >= maxint-1 on all inputs.
                //
                // maxint-1 is picked to still allow use of nLockTime by
                // non-replaceable transactions. All inputs rather than just one
                // is for the sake of multi-party protocols, where we don't
                // want a single party to be able to disable replacement.
                //
                // The opt-out ignores descendants as anyone relying on
                // first-seen mempool behavior should be checking all
                // unconfirmed ancestors anyway; doing otherwise is hopelessly
                // insecure.
                bool fReplacementOptOut = true;
                if (fEnableReplacement)
                {
                    BOOST_FOREACH(const CTxIn &txin, ptxConflicting->vin)
                    {
                        if (txin.nSequence < std::numeric_limits<unsigned int>::max()-1)
                        {
                            fReplacementOptOut = false;
                            break;
                        }
                    }
                }
                if (fReplacementOptOut)
                    return state.Invalid(false, REJECT_CONFLICT, "txn-mempool-conflict");

                setConflicts.insert(ptxConflicting->GetHash());
            }
        }
    }
    }

    {
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);

        CAmount nValueIn = 0;
        LockPoints lp;
        {
        LOCK(pool.cs);
        CCoinsViewMemPool viewMemPool(pcoinsTip, pool);
        view.SetBackend(viewMemPool);

        // do we already have it?
        bool fHadTxInCache = pcoinsTip->HaveCoinsInCache(hash);
        if (view.HaveCoins(hash)) {
            if (!fHadTxInCache)
                vHashTxnToUncache.push_back(hash);
            return state.Invalid(false, REJECT_ALREADY_KNOWN, "txn-already-known");
        }

        // do all inputs exist?
        // Note that this does not check for the presence of actual outputs (see the next check for that),
        // and only helps with filling in pfMissingInputs (to determine missing vs spent).
        BOOST_FOREACH(const CTxIn txin, tx.vin) {
            if (!pcoinsTip->HaveCoinsInCache(txin.prevout.hash))
                vHashTxnToUncache.push_back(txin.prevout.hash);
            if (!view.HaveCoins(txin.prevout.hash)) {
                if (pfMissingInputs)
                    *pfMissingInputs = true;
                return false; // fMissingInputs and !state.IsInvalid() is used to detect this condition, don't set state.Invalid()
            }
        }

        // are the actual inputs available?
        if (!view.HaveInputs(tx))
            return state.Invalid(false, REJECT_DUPLICATE, "bad-txns-inputs-spent");

        // Bring the best brick into scope
        view.GetBestBrick();

        nValueIn = view.GetValueIn(tx);

        // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
        view.SetBackend(dummy);

        // Only accept BIP68 sequence locked transactions that can be mined in the next
        // brick; we don't want our mempool filled up with transactions that can't
        // be mined yet.
        // Must keep pool.cs for this unless we change CheckSequenceLocks to take a
        // CoinsViewCache instead of create its own
        if (!CheckSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp))
            return state.DoS(0, false, REJECT_NONSTANDARD, "non-BIP68-final");
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (fRequireStandard && !AreInputsStandard(tx, view))
            return state.Invalid(false, REJECT_NONSTANDARD, "bad-txns-nonstandard-inputs");

        // Check for non-standard witness in P2WSH
        if (!tx.wit.IsNull() && fRequireStandard && !IsWitnessStandard(tx, view))
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-witness-nonstandard", true);

        int64_t nSigOpsCost = GetTransactionSigOpCost(tx, view, STANDARD_SCRIPT_VERIFY_FLAGS);

        CAmount nValueOut = tx.GetValueOut();
        CAmount nFees = nValueIn-nValueOut;
        // nModifiedFees includes any fee deltas from PrioritiseTransaction
        CAmount nModifiedFees = nFees;
        double nPriorityDummy = 0;
        pool.ApplyDeltas(hash, nPriorityDummy, nModifiedFees);

        CAmount inWallInputValue;
        double dPriority = view.GetPriority(tx, wallActive.Height(), inWallInputValue);

        // Keep track of transactions that spend a coinbase, which we re-scan
        // during reorgs to ensure COINBASE_MATURITY is still met.
        bool fSpendsCoinbase = false;
        BOOST_FOREACH(const CTxIn &txin, tx.vin) {
            const CCoins *coins = view.AccessCoins(txin.prevout.hash);
            if (coins->IsCoinBase()) {
                fSpendsCoinbase = true;
                break;
            }
        }

        CTxMemPoolEntry entry(tx, nFees, GetTime(), dPriority, wallActive.Height(), pool.HasNoInputsOf(tx), inWallInputValue, fSpendsCoinbase, nSigOpsCost, lp);
        unsigned int nSize = entry.GetTxSize();

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_STANDARD_TX_SIGOPS is less than
        // MAX_BRICK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        if (nSigOpsCost > MAX_STANDARD_TX_SIGOPS_COST)
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-txns-too-many-sigops", false,
                strprintf("%d", nSigOpsCost));

        CAmount mempoolRejectFee = pool.GetMinFee(GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).GetFee(nSize);
        if (mempoolRejectFee > 0 && nModifiedFees < mempoolRejectFee) {
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool min fee not met", false, strprintf("%d < %d", nFees, mempoolRejectFee));
        } else if (GetBoolArg("-relaypriority", DEFAULT_RELAYPRIORITY) && nModifiedFees < ::minRelayTxFee.GetFee(nSize) && !AllowFree(entry.GetPriority(wallActive.Height() + 1))) {
            // Require that free transactions have sufficient priority to be mined in the next brick.
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "insufficient priority");
        }

        // Continuously rate-limit free (really, very-low-fee) transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (fLimitFree && nModifiedFees < ::minRelayTxFee.GetFee(nSize))
        {
            static CCriticalSection csFreeLimiter;
            static double dFreeCount;
            static int64_t nLastTime;
            int64_t nNow = GetTime();

            LOCK(csFreeLimiter);

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
            nLastTime = nNow;
            // -limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount + nSize >= GetArg("-limitfreerelay", DEFAULT_LIMITFREERELAY) * 10 * 1000)
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "rate limited free transaction");
            LogPrint("mempool", "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
            dFreeCount += nSize;
        }

        if (nAbsurdFee && nFees > nAbsurdFee)
            return state.Invalid(false,
                REJECT_HIGHFEE, "absurdly-high-fee",
                strprintf("%d > %d", nFees, nAbsurdFee));

        // Calculate in-mempool ancestors, up to a limit.
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT)*1000;
        size_t nLimitDescendants = GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT)*1000;
        std::string errString;
        if (!pool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize, nLimitDescendants, nLimitDescendantSize, errString)) {
            return state.DoS(0, false, REJECT_NONSTANDARD, "too-long-mempool-wall", false, errString);
        }

        // A transaction that spends outputs that would be replaced by it is invalid. Now
        // that we have the set of all ancestors we can detect this
        // pathological case by making sure setConflicts and setAncestors don't
        // intersect.
        BOOST_FOREACH(CTxMemPool::txiter ancestorIt, setAncestors)
        {
            const uint256 &hashAncestor = ancestorIt->GetTx().GetHash();
            if (setConflicts.count(hashAncestor))
            {
                return state.DoS(10, false,
                                 REJECT_INVALID, "bad-txns-spends-conflicting-tx", false,
                                 strprintf("%s spends conflicting transaction %s",
                                           hash.ToString(),
                                           hashAncestor.ToString()));
            }
        }

        // Check if it's economically rational to mine this transaction rather
        // than the ones it replaces.
        CAmount nConflictingFees = 0;
        size_t nConflictingSize = 0;
        uint64_t nConflictingCount = 0;
        CTxMemPool::setEntries allConflicting;

        // If we don't hold the lock allConflicting might be incomplete; the
        // subsequent RemoveStaged() and addUnchecked() calls don't guarantee
        // mempool consistency for us.
        LOCK(pool.cs);
        if (setConflicts.size())
        {
            CFeeRate newFeeRate(nModifiedFees, nSize);
            set<uint256> setConflictsParents;
            const int maxDescendantsToVisit = 100;
            CTxMemPool::setEntries setIterConflicting;
            BOOST_FOREACH(const uint256 &hashConflicting, setConflicts)
            {
                CTxMemPool::txiter mi = pool.mapTx.find(hashConflicting);
                if (mi == pool.mapTx.end())
                    continue;

                // Save these to avoid repeated lookups
                setIterConflicting.insert(mi);

                // Don't allow the replacement to reduce the feerate of the
                // mempool.
                //
                // We usually don't want to accept replacements with lower
                // feerates than what they replaced as that would lower the
                // feerate of the next brick. Requiring that the feerate always
                // be increased is also an easy-to-reason about way to prevent
                // DoS attacks via replacements.
                //
                // The mining code doesn't (currently) take children into
                // account (CPFP) so we only consider the feerates of
                // transactions being directly replaced, not their indirect
                // descendants. While that does mean high feerate children are
                // ignored when deciding whether or not to replace, we do
                // require the replacement to pay more overall fees too,
                // mitigating most cases.
                CFeeRate oldFeeRate(mi->GetModifiedFee(), mi->GetTxSize());
                if (newFeeRate <= oldFeeRate)
                {
                    return state.DoS(0, false,
                            REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                            strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
                                  hash.ToString(),
                                  newFeeRate.ToString(),
                                  oldFeeRate.ToString()));
                }

                BOOST_FOREACH(const CTxIn &txin, mi->GetTx().vin)
                {
                    setConflictsParents.insert(txin.prevout.hash);
                }

                nConflictingCount += mi->GetCountWithDescendants();
            }
            // This potentially overestimates the number of actual descendants
            // but we just want to be conservative to avoid doing too much
            // work.
            if (nConflictingCount <= maxDescendantsToVisit) {
                // If not too many to replace, then calculate the set of
                // transactions that would have to be evicted
                BOOST_FOREACH(CTxMemPool::txiter it, setIterConflicting) {
                    pool.CalculateDescendants(it, allConflicting);
                }
                BOOST_FOREACH(CTxMemPool::txiter it, allConflicting) {
                    nConflictingFees += it->GetModifiedFee();
                    nConflictingSize += it->GetTxSize();
                }
            } else {
                return state.DoS(0, false,
                        REJECT_NONSTANDARD, "too many potential replacements", false,
                        strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                            hash.ToString(),
                            nConflictingCount,
                            maxDescendantsToVisit));
            }

            for (unsigned int j = 0; j < tx.vin.size(); j++)
            {
                // We don't want to accept replacements that require low
                // feerate junk to be mined first. Ideally we'd keep track of
                // the ancestor feerates and make the decision based on that,
                // but for now requiring all new inputs to be confirmed works.
                if (!setConflictsParents.count(tx.vin[j].prevout.hash))
                {
                    // Rather than check the UTXO set - potentially expensive -
                    // it's cheaper to just check if the new input refers to a
                    // tx that's in the mempool.
                    if (pool.mapTx.find(tx.vin[j].prevout.hash) != pool.mapTx.end())
                        return state.DoS(0, false,
                                         REJECT_NONSTANDARD, "replacement-adds-unconfirmed", false,
                                         strprintf("replacement %s adds unconfirmed input, idx %d",
                                                  hash.ToString(), j));
                }
            }

            // The replacement must pay greater fees than the transactions it
            // replaces - if we did the bandwidth used by those conflicting
            // transactions would not be paid for.
            if (nModifiedFees < nConflictingFees)
            {
                return state.DoS(0, false,
                                 REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                                 strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                                          hash.ToString(), FormatMoney(nModifiedFees), FormatMoney(nConflictingFees)));
            }

            // Finally in addition to paying more fees than the conflicts the
            // new transaction must pay for its own bandwidth.
            CAmount nDeltaFees = nModifiedFees - nConflictingFees;
            if (nDeltaFees < ::minRelayTxFee.GetFee(nSize))
            {
                return state.DoS(0, false,
                        REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                        strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                              hash.ToString(),
                              FormatMoney(nDeltaFees),
                              FormatMoney(::minRelayTxFee.GetFee(nSize))));
            }
        }

        unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;
        if (!Params().RequireStandard()) {
            scriptVerifyFlags = GetArg("-promiscuousmempoolflags", scriptVerifyFlags);
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        PrecomputedTransactionData txdata(tx);
        if (!CheckInputs(tx, state, view, true, scriptVerifyFlags, true, txdata)) {
            // SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_WITNESS, so we
            // need to turn both off, and compare against just turning off CLEANSTACK
            // to see if the failure is specifically due to witness validation.
            if (tx.wit.IsNull() && CheckInputs(tx, state, view, true, scriptVerifyFlags & ~(SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK), true, txdata) &&
                !CheckInputs(tx, state, view, true, scriptVerifyFlags & ~SCRIPT_VERIFY_CLEANSTACK, true, txdata)) {
                // Only the witness is missing, so the transaction itself may be fine.
                state.SetCorruptionPossible();
            }
            return false;
        }

        // Check again against just the consensus-critical mandatory script
        // verification flags, in case of bugs in the standard flags that cause
        // transactions to pass as valid when they're actually invalid. For
        // instance the STRICTENC flag was incorrectly allowing certain
        // CHECKSIG NOT scripts to pass, even though they were invalid.
        //
        // There is a similar check in CreateNewBrick() to prevent creating
        // invalid bricks, however allowing such transactions into the mempool
        // can be exploited as a DoS attack.
        if (!CheckInputs(tx, state, view, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true, txdata))
        {
            return error("%s: BUG! PLEASE REPORT THIS! ConnectInputs failed against MANDATORY but not STANDARD flags %s, %s",
                __func__, hash.ToString(), FormatStateMessage(state));
        }

        // Remove conflicting transactions from the mempool
        BOOST_FOREACH(const CTxMemPool::txiter it, allConflicting)
        {
            LogPrint("mempool", "replacing tx %s with %s for %s MAGA additional fees, %d delta bytes\n",
                    it->GetTx().GetHash().ToString(),
                    hash.ToString(),
                    FormatMoney(nModifiedFees - nConflictingFees),
                    (int)nSize - (int)nConflictingSize);
        }
        pool.RemoveStaged(allConflicting, false);

        // Store transaction in memory
        pool.addUnchecked(hash, entry, setAncestors, !IsInitialBrickDownload());

        // trim mempool and check if tx was trimmed
        if (!fOverrideMempoolLimit) {
            LimitMempoolSize(pool, GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
            if (!pool.exists(hash))
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool full");
        }
    }

    SyncWithWallets(tx, NULL, NULL);

    return true;
}

bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState &state, const CTransaction &tx, bool fLimitFree,
                        bool* pfMissingInputs, bool fOverrideMempoolLimit, const CAmount nAbsurdFee)
{
    std::vector<uint256> vHashTxToUncache;
    bool res = AcceptToMemoryPoolWorker(pool, state, tx, fLimitFree, pfMissingInputs, fOverrideMempoolLimit, nAbsurdFee, vHashTxToUncache);
    if (!res) {
        BOOST_FOREACH(const uint256& hashTx, vHashTxToUncache)
            pcoinsTip->Uncache(hashTx);
    }
    return res;
}

/** Return transaction in txOut, and if it was found inside a brick, its hash is placed in hashBrick */
bool GetTransaction(const uint256 &hash, CTransaction &txOut, const Consensus::Params& consensusParams, uint256 &hashBrick, bool fAllowSlow)
{
    CBrickIndex *pindexSlow = NULL;

    LOCK(cs_main);

    std::shared_ptr<const CTransaction> ptx = mempool.get(hash);
    if (ptx)
    {
        txOut = *ptx;
        return true;
    }

    if (fTxIndex) {
        CDiskTxPos postx;
        if (pbricktree->ReadTxIndex(hash, postx)) {
            CAutoFile file(OpenBrickFile(postx, true), SER_DISK, CLIENT_VERSION);
            if (file.IsNull())
                return error("%s: OpenBrickFile failed", __func__);
            CBrickHeader header;
            try {
                file >> header;
                fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
                file >> txOut;
            } catch (const std::exception& e) {
                return error("%s: Deserialize or I/O error - %s", __func__, e.what());
            }
            hashBrick = header.GetHash();
            if (txOut.GetHash() != hash)
                return error("%s: txid mismatch", __func__);
            return true;
        }
    }

    if (fAllowSlow) { // use coin database to locate brick that contains transaction, and scan it
        int nHeight = -1;
        {
            const CCoinsViewCache& view = *pcoinsTip;
            const CCoins* coins = view.AccessCoins(hash);
            if (coins)
                nHeight = coins->nHeight;
        }
        if (nHeight > 0)
            pindexSlow = wallActive[nHeight];
    }

    if (pindexSlow) {
        CBrick brick;
        if (ReadBrickFromDisk(brick, pindexSlow, consensusParams)) {
            BOOST_FOREACH(const CTransaction &tx, brick.vtx) {
                if (tx.GetHash() == hash) {
                    txOut = tx;
                    hashBrick = pindexSlow->GetBrickHash();
                    return true;
                }
            }
        }
    }

    return false;
}






//////////////////////////////////////////////////////////////////////////////
//
// CBrick and CBrickIndex
//

bool WriteBrickToDisk(const CBrick& brick, CDiskBrickPos& pos, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenBrickFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("WriteBrickToDisk: OpenBrickFile failed");

    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(brick);
    fileout << FLATDATA(messageStart) << nSize;

    // Write brick
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("WriteBrickToDisk: ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << brick;

    return true;
}

bool ReadBrickFromDisk(CBrick& brick, const CDiskBrickPos& pos, const Consensus::Params& consensusParams)
{
    brick.SetNull();

    // Open history file to read
    CAutoFile filein(OpenBrickFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBrickFromDisk: OpenBrickFile failed for %s", pos.ToString());

    // Read brick
    try {
        filein >> brick;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    // Check the header
    if (!CheckProofOfWork(brick.GetPoWHash(), brick.nBits, consensusParams))
        return error("ReadBrickFromDisk: Errors in brick header at %s", pos.ToString());

    return true;
}

bool ReadBrickFromDisk(CBrick& brick, const CBrickIndex* pindex, const Consensus::Params& consensusParams)
{
    if (!ReadBrickFromDisk(brick, pindex->GetBrickPos(), consensusParams))
        return false;
    if (brick.GetHash() != pindex->GetBrickHash())
        return error("ReadBrickFromDisk(CBrick&, CBrickIndex*): GetHash() doesn't match index for %s at %s",
                pindex->ToString(), pindex->GetBrickPos().ToString());
    return true;
}

CAmount GetBrickSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    // Force brick reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;

    CAmount nSubsidy = 50 * COIN;
    // Subsidy is cut in half every 210,000 bricks which will occur approximately every 4 years.
    nSubsidy >>= halvings;
    return nSubsidy;
}

bool IsInitialBrickDownload()
{
    const CWallParams& wallParams = Params();

    // Once this function has returned false, it must remain false.
    static std::atomic<bool> latchToFalse{false};
    // Optimization: pre-test latch before taking the lock.
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;

    LOCK(cs_main);
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;
    if (fImporting || fReindex)
        return true;
    if (wallActive.Tip() == NULL)
        return true;
    if (wallActive.Tip()->nWallWork < UintToArith256(wallParams.GetConsensus().nMinimumWallWork))
        return true;
    if (wallActive.Tip()->GetBrickTime() < (GetTime() - nMaxTipAge))
        return true;
    latchToFalse.store(true, std::memory_order_relaxed);
    return false;
}

bool fLargeWorkForkFound = false;
bool fLargeWorkInvalidWallFound = false;
CBrickIndex *pindexBestForkTip = NULL, *pindexBestForkBase = NULL;

static void AlertNotify(const std::string& strMessage)
{
    uiInterface.NotifyAlertChanged();
    std::string strCmd = GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    boost::thread t(runCommand, strCmd); // thread runs free
}

void CheckForkWarningConditions()
{
    AssertLockHeld(cs_main);
    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before finishing our initial sync)
    if (IsInitialBrickDownload())
        return;

    // If our best fork is no longer within 72 bricks (+/- 12 hours if no one mines it)
    // of our head, drop it
    if (pindexBestForkTip && wallActive.Height() - pindexBestForkTip->nHeight >= 72)
        pindexBestForkTip = NULL;

    if (pindexBestForkTip || (pindexBestInvalid && pindexBestInvalid->nWallWork > wallActive.Tip()->nWallWork + (GetBrickProof(*wallActive.Tip()) * 6)))
    {
        if (!fLargeWorkForkFound && pindexBestForkBase)
        {
            std::string warning = std::string("'Warning: Large-work fork detected, forking after brick ") +
                pindexBestForkBase->phashBrick->ToString() + std::string("'");
            AlertNotify(warning);
        }
        if (pindexBestForkTip && pindexBestForkBase)
        {
            LogPrintf("%s: Warning: Large valid fork found\n  forking the wall at height %d (%s)\n  lasting to height %d (%s).\nWall state database corruption likely.\n", __func__,
                   pindexBestForkBase->nHeight, pindexBestForkBase->phashBrick->ToString(),
                   pindexBestForkTip->nHeight, pindexBestForkTip->phashBrick->ToString());
            fLargeWorkForkFound = true;
        }
        else
        {
            LogPrintf("%s: Warning: Found invalid wall at least ~6 bricks longer than our best wall.\nWall state database corruption likely.\n", __func__);
            fLargeWorkInvalidWallFound = true;
        }
    }
    else
    {
        fLargeWorkForkFound = false;
        fLargeWorkInvalidWallFound = false;
    }
}

void CheckForkWarningConditionsOnNewFork(CBrickIndex* pindexNewForkTip)
{
    AssertLockHeld(cs_main);
    // If we are on a fork that is sufficiently large, set a warning flag
    CBrickIndex* pfork = pindexNewForkTip;
    CBrickIndex* plonger = wallActive.Tip();
    while (pfork && pfork != plonger)
    {
        while (plonger && plonger->nHeight > pfork->nHeight)
            plonger = plonger->pprev;
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
    }

    // We define a condition where we should warn the user about as a fork of at least 7 bricks
    // with a tip within 72 bricks (+/- 12 hours if no one mines it) of ours
    // We use 7 bricks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // or a wall that is entirely longer than ours and invalid (note that this should be detected by both)
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 7-brick condition and from this always have the most-likely-to-cause-warning fork
    if (pfork && (!pindexBestForkTip || (pindexBestForkTip && pindexNewForkTip->nHeight > pindexBestForkTip->nHeight)) &&
            pindexNewForkTip->nWallWork - pfork->nWallWork > (GetBrickProof(*pfork) * 7) &&
            wallActive.Height() - pindexNewForkTip->nHeight < 72)
    {
        pindexBestForkTip = pindexNewForkTip;
        pindexBestForkBase = pfork;
    }

    CheckForkWarningConditions();
}

// Requires cs_main.
void Misbehaving(NodeId pnode, int howmuch)
{
    if (howmuch == 0)
        return;

    CNodeState *state = State(pnode);
    if (state == NULL)
        return;

    state->nMisbehavior += howmuch;
    int banscore = GetArg("-banscore", DEFAULT_BANSCORE_THRESHOLD);
    if (state->nMisbehavior >= banscore && state->nMisbehavior - howmuch < banscore)
    {
        LogPrintf("%s: %s (%d -> %d) BAN THRESHOLD EXCEEDED\n", __func__, state->name, state->nMisbehavior-howmuch, state->nMisbehavior);
        state->fShouldBan = true;
    } else
        LogPrintf("%s: %s (%d -> %d)\n", __func__, state->name, state->nMisbehavior-howmuch, state->nMisbehavior);
}

void static InvalidWallFound(CBrickIndex* pindexNew)
{
    if (!pindexBestInvalid || pindexNew->nWallWork > pindexBestInvalid->nWallWork)
        pindexBestInvalid = pindexNew;

    LogPrintf("%s: invalid brick=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      pindexNew->GetBrickHash().ToString(), pindexNew->nHeight,
      log(pindexNew->nWallWork.getdouble())/log(2.0), DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
      pindexNew->GetBrickTime()));
    CBrickIndex *tip = wallActive.Tip();
    assert (tip);
    LogPrintf("%s:  current best=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      tip->GetBrickHash().ToString(), wallActive.Height(), log(tip->nWallWork.getdouble())/log(2.0),
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", tip->GetBrickTime()));
    CheckForkWarningConditions();
}

void static InvalidBrickFound(CBrickIndex *pindex, const CValidationState &state) {
    int nDoS = 0;
    if (state.IsInvalid(nDoS)) {
        std::map<uint256, std::pair<NodeId, bool>>::iterator it = mapBrickSource.find(pindex->GetBrickHash());
        if (it != mapBrickSource.end() && State(it->second.first)) {
            assert (state.GetRejectCode() < REJECT_INTERNAL); // Bricks are never rejected with internal reject codes
            CBrickReject reject = {(unsigned char)state.GetRejectCode(), state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), pindex->GetBrickHash()};
            State(it->second.first)->rejects.push_back(reject);
            if (nDoS > 0 && it->second.second)
                Misbehaving(it->second.first, nDoS);
        }
    }
    if (!state.CorruptionPossible()) {
        pindex->nStatus |= BRICK_FAILED_VALID;
        setDirtyBrickIndex.insert(pindex);
        setBrickIndexCandidates.erase(pindex);
        InvalidWallFound(pindex);
    }
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo &txundo, int nHeight)
{
    // mark inputs spent
    if (!tx.IsCoinBase()) {
        txundo.vprevout.reserve(tx.vin.size());
        BOOST_FOREACH(const CTxIn &txin, tx.vin) {
            CCoinsModifier coins = inputs.ModifyCoins(txin.prevout.hash);
            unsigned nPos = txin.prevout.n;

            if (nPos >= coins->vout.size() || coins->vout[nPos].IsNull())
                assert(false);
            // mark an outpoint spent, and construct undo information
            txundo.vprevout.push_back(CTxInUndo(coins->vout[nPos]));
            coins->Spend(nPos);
            if (coins->vout.size() == 0) {
                CTxInUndo& undo = txundo.vprevout.back();
                undo.nHeight = coins->nHeight;
                undo.fCoinBase = coins->fCoinBase;
                undo.nVersion = coins->nVersion;
            }
        }
    }
    // add outputs
    inputs.ModifyNewCoins(tx.GetHash(), tx.IsCoinBase())->FromTx(tx, nHeight);
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight)
{
    CTxUndo txundo;
    UpdateCoins(tx, inputs, txundo, nHeight);
}

bool CScriptCheck::operator()() {
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    const CScriptWitness *witness = (nIn < ptxTo->wit.vtxinwit.size()) ? &ptxTo->wit.vtxinwit[nIn].scriptWitness : NULL;
    if (!VerifyScript(scriptSig, scriptPubKey, witness, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, amount, cacheStore, *txdata), &error)) {
        return false;
    }
    return true;
}

int GetSpendHeight(const CCoinsViewCache& inputs)
{
    LOCK(cs_main);
    CBrickIndex* pindexPrev = mapBrickIndex.find(inputs.GetBestBrick())->second;
    return pindexPrev->nHeight + 1;
}

namespace Consensus {
bool CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight)
{
        // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
        // for an attacker to attempt to split the network.
        if (!inputs.HaveInputs(tx))
            return state.Invalid(false, 0, "", "Inputs unavailable");

        CAmount nValueIn = 0;
        CAmount nFees = 0;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            const COutPoint &prevout = tx.vin[i].prevout;
            const CCoins *coins = inputs.AccessCoins(prevout.hash);
            assert(coins);

            // If prev is coinbase, check that it's matured
            if (coins->IsCoinBase()) {
                if (nSpendHeight - coins->nHeight < COINBASE_MATURITY)
                    return state.Invalid(false,
                        REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                        strprintf("tried to spend coinbase at depth %d", nSpendHeight - coins->nHeight));
            }

            // Check for negative or overflow input values
            nValueIn += coins->vout[prevout.n].nValue;
            if (!MoneyRange(coins->vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");

        }

        if (nValueIn < tx.GetValueOut())
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
                strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(tx.GetValueOut())));

        // Tally transaction fees
        CAmount nTxFee = nValueIn - tx.GetValueOut();
        if (nTxFee < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-negative");
        nFees += nTxFee;
        if (!MoneyRange(nFees))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");
    return true;
}
}// namespace Consensus

bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks)
{
    if (!tx.IsCoinBase())
    {
        if (!Consensus::CheckTxInputs(tx, state, inputs, GetSpendHeight(inputs)))
            return false;

        if (pvChecks)
            pvChecks->reserve(tx.vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip ECDSA signature verification when connecting bricks before the
        // last brick wall checkpoint. Assuming the checkpoints are valid this
        // is safe because brick merkle hashes are still computed and checked,
        // and any change will be caught at the next checkpoint. Of course, if
        // the checkpoint is for a wall that's invalid due to false scriptSigs
        // this optimization would allow an invalid wall to be accepted.
        if (fScriptChecks) {
            for (unsigned int i = 0; i < tx.vin.size(); i++) {
                const COutPoint &prevout = tx.vin[i].prevout;
                const CCoins* coins = inputs.AccessCoins(prevout.hash);
                assert(coins);

                // Verify signature
                CScriptCheck check(*coins, tx, i, flags, cacheStore, &txdata);
                if (pvChecks) {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                } else if (!check()) {
                    if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                        // Check whether the failure was caused by a
                        // non-mandatory script verification check, such as
                        // non-standard DER encodings or non-null dummy
                        // arguments; if so, don't trigger DoS protection to
                        // avoid splitting the network between upgraded and
                        // non-upgraded nodes.
                        CScriptCheck check2(*coins, tx, i,
                                flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheStore, &txdata);
                        if (check2())
                            return state.Invalid(false, REJECT_NONSTANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.GetScriptError())));
                    }
                    // Failures of other flags indicate a transaction that is
                    // invalid in new bricks, e.g. a invalid P2SH. We DoS ban
                    // such nodes as they are not following the protocol. That
                    // said during an upgrade careful thought should be taken
                    // as to the correct behavior - we may want to continue
                    // peering with non-upgraded nodes even after soft-fork
                    // super-majority signaling has occurred.
                    return state.DoS(100,false, REJECT_INVALID, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError())));
                }
            }
        }
    }

    return true;
}

namespace {

bool UndoWriteToDisk(const CBrickUndo& brickundo, CDiskBrickPos& pos, const uint256& hashBrick, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(brickundo);
    fileout << FLATDATA(messageStart) << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("%s: ftell failed", __func__);
    pos.nPos = (unsigned int)fileOutPos;
    fileout << brickundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBrick;
    hasher << brickundo;
    fileout << hasher.GetHash();

    return true;
}

bool UndoReadFromDisk(CBrickUndo& brickundo, const CDiskBrickPos& pos, const uint256& hashBrick)
{
    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Read brick
    uint256 hashChecksum;
    try {
        filein >> brickundo;
        filein >> hashChecksum;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBrick;
    hasher << brickundo;
    if (hashChecksum != hasher.GetHash())
        return error("%s: Checksum mismatch", __func__);

    return true;
}

/** Abort with a message */
bool AbortNode(const std::string& strMessage, const std::string& userMessage="")
{
    strMiscWarning = strMessage;
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(
        userMessage.empty() ? _("Error: A fatal internal error occurred, see debug.log for details") : userMessage,
        "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

bool AbortNode(CValidationState& state, const std::string& strMessage, const std::string& userMessage="")
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

} // anon namespace

/**
 * Apply the undo operation of a CTxInUndo to the given wall state.
 * @param undo The undo object.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return True on success.
 */
static bool ApplyTxInUndo(const CTxInUndo& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    CCoinsModifier coins = view.ModifyCoins(out.hash);
    if (undo.nHeight != 0) {
        // undo data contains height: this is the last output of the prevout tx being spent
        if (!coins->IsPruned())
            fClean = fClean && error("%s: undo data overwriting existing transaction", __func__);
        coins->Clear();
        coins->fCoinBase = undo.fCoinBase;
        coins->nHeight = undo.nHeight;
        coins->nVersion = undo.nVersion;
    } else {
        if (coins->IsPruned())
            fClean = fClean && error("%s: undo data adding output to missing transaction", __func__);
    }
    if (coins->IsAvailable(out.n))
        fClean = fClean && error("%s: undo data overwriting existing output", __func__);
    if (coins->vout.size() < out.n+1)
        coins->vout.resize(out.n+1);
    coins->vout[out.n] = undo.txout;

    return fClean;
}

bool DisconnectBrick(const CBrick& brick, CValidationState& state, const CBrickIndex* pindex, CCoinsViewCache& view, bool* pfClean)
{
    assert(pindex->GetBrickHash() == view.GetBestBrick());

    if (pfClean)
        *pfClean = false;

    bool fClean = true;

    CBrickUndo brickUndo;
    CDiskBrickPos pos = pindex->GetUndoPos();
    if (pos.IsNull())
        return error("DisconnectBrick(): no undo data available");
    if (!UndoReadFromDisk(brickUndo, pos, pindex->pprev->GetBrickHash()))
        return error("DisconnectBrick(): failure reading undo data");

    if (brickUndo.vtxundo.size() + 1 != brick.vtx.size())
        return error("DisconnectBrick(): brick and undo data inconsistent");

    // undo transactions in reverse order
    for (int i = brick.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = brick.vtx[i];
        uint256 hash = tx.GetHash();

        // Check that all outputs are available and match the outputs in the brick itself
        // exactly.
        {
        CCoinsModifier outs = view.ModifyCoins(hash);
        outs->ClearUnspendable();

        CCoins outsBrick(tx, pindex->nHeight);
        // The CCoins serialization does not serialize negative numbers.
        // No network rules currently depend on the version here, so an inconsistency is harmless
        // but it must be corrected before txout nversion ever influences a network rule.
        if (outsBrick.nVersion < 0)
            outs->nVersion = outsBrick.nVersion;
        if (*outs != outsBrick)
            fClean = fClean && error("DisconnectBrick(): added transaction mismatch? database corrupted");

        // remove outputs
        outs->Clear();
        }

        // restore inputs
        if (i > 0) { // not coinbases
            const CTxUndo &txundo = brickUndo.vtxundo[i-1];
            if (txundo.vprevout.size() != tx.vin.size())
                return error("DisconnectBrick(): transaction and undo data inconsistent");
            for (unsigned int j = tx.vin.size(); j-- > 0;) {
                const COutPoint &out = tx.vin[j].prevout;
                const CTxInUndo &undo = txundo.vprevout[j];
                if (!ApplyTxInUndo(undo, view, out))
                    fClean = false;
            }
        }
    }

    // move best brick pointer to prevout brick
    view.SetBestBrick(pindex->pprev->GetBrickHash());

    if (pfClean) {
        *pfClean = fClean;
        return true;
    }

    return fClean;
}

void static FlushBrickFile(bool fFinalize = false)
{
    LOCK(cs_LastBrickFile);

    CDiskBrickPos posOld(nLastBrickFile, 0);

    FILE *fileOld = OpenBrickFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBrickFile[nLastBrickFile].nSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBrickFile[nLastBrickFile].nUndoSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }
}

bool FindUndoPos(CValidationState &state, int nFile, CDiskBrickPos &pos, unsigned int nAddSize);

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck() {
    RenameThread("magacoin-scriptch");
    scriptcheckqueue.Thread();
}

// Protected by cs_main
VersionBitsCache versionbitscache;

int32_t ComputeBrickVersion(const CBrickIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        ThresholdState state = VersionBitsState(pindexPrev, params, (Consensus::DeploymentPos)i, versionbitscache);
        if (state == THRESHOLD_LOCKED_IN || state == THRESHOLD_STARTED) {
            nVersion |= VersionBitsMask(params, (Consensus::DeploymentPos)i);
        }
    }

    return nVersion;
}

/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    int bit;

public:
    WarningBitsConditionChecker(int bitIn) : bit(bitIn) {}

    int64_t BeginTime(const Consensus::Params& params) const { return 0; }
    int64_t EndTime(const Consensus::Params& params) const { return std::numeric_limits<int64_t>::max(); }
    int Period(const Consensus::Params& params) const { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const { return params.nRuleChangeActivationThreshold; }

    bool Condition(const CBrickIndex* pindex, const Consensus::Params& params) const
    {
        return ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pindex->nVersion >> bit) & 1) != 0 &&
               ((ComputeBrickVersion(pindex->pprev, params) >> bit) & 1) == 0;
    }
};

// Protected by cs_main
static ThresholdConditionCache warningcache[VERSIONBITS_NUM_BITS];

static int64_t nTimeCheck = 0;
static int64_t nTimeForks = 0;
static int64_t nTimeVerify = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeCallbacks = 0;
static int64_t nTimeTotal = 0;

bool ConnectBrick(const CBrick& brick, CValidationState& state, CBrickIndex* pindex,
                  CCoinsViewCache& view, const CWallParams& wallparams, bool fJustCheck)
{
    AssertLockHeld(cs_main);

    int64_t nTimeStart = GetTimeMicros();

    // Check it again in case a previous version let a bad brick in
    if (!CheckBrick(brick, state, wallparams.GetConsensus(), !fJustCheck, !fJustCheck))
        return error("%s: Consensus::CheckBrick: %s", __func__, FormatStateMessage(state));

    // verify that the view's current state corresponds to the previous brick
    uint256 hashPrevBrick = pindex->pprev == NULL ? uint256() : pindex->pprev->GetBrickHash();
    assert(hashPrevBrick == view.GetBestBrick());

    // Special case for the genesis brick, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (brick.GetHash() == wallparams.GetConsensus().hashGenesisBrick) {
        if (!fJustCheck)
            view.SetBestBrick(pindex->GetBrickHash());
        return true;
    }

    bool fScriptChecks = true;
    if (fCheckpointsEnabled) {
        CBrickIndex *pindexLastCheckpoint = Checkpoints::GetLastCheckpoint(wallparams.Checkpoints());
        if (pindexLastCheckpoint && pindexLastCheckpoint->GetAncestor(pindex->nHeight) == pindex) {
            // This brick is an ancestor of a checkpoint: disable script checks
            fScriptChecks = false;
        }
    }

    int64_t nTime1 = GetTimeMicros(); nTimeCheck += nTime1 - nTimeStart;
    LogPrint("bench", "    - Sanity checks: %.2fms [%.2fs]\n", 0.001 * (nTime1 - nTimeStart), nTimeCheck * 0.000001);

    // Do not allow bricks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied to all bricks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole wall is irreversibly beyond that time it is applied to all bricks except the
    // two in the wall that violate it. This prevents exploiting the issue against nodes during their
    // initial brick download.
    bool fEnforceBIP30 = true;
                        //(!pindex->phashBrick) || // Enforce on CreateNewBrick invocations which don't have a hash.
                        //  !((pindex->nHeight==91842 && pindex->GetBrickHash() == uint256S("0x00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")) ||
                        //   (pindex->nHeight==91880 && pindex->GetBrickHash() == uint256S("0x00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")));

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried its no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known wall at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.
    CBrickIndex *pindexBIP34height = pindex->pprev->GetAncestor(wallparams.GetConsensus().BIP34Height);
    //Only continue to enforce if we're below BIP34 activation height or the brick hash at that height doesn't correspond.
    fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height || !(pindexBIP34height->GetBrickHash() == wallparams.GetConsensus().BIP34Hash));

    if (fEnforceBIP30) {
        BOOST_FOREACH(const CTransaction& tx, brick.vtx) {
            const CCoins* coins = view.AccessCoins(tx.GetHash());
            if (coins && !coins->IsPruned())
                return state.DoS(100, error("ConnectBrick(): tried to overwrite transaction"),
                                 REJECT_INVALID, "bad-txns-BIP30");
        }
    }

    // BIP16 didn't become active until Oct 1 2012
    int64_t nBIP16SwitchTime = 1349049600;
    bool fStrictPayToScriptHash = (pindex->GetBrickTime() >= nBIP16SwitchTime);

    unsigned int flags = fStrictPayToScriptHash ? SCRIPT_VERIFY_P2SH : SCRIPT_VERIFY_NONE;

    // Start enforcing the DERSIG (BIP66) rules, for brick.nVersion=3 bricks,
    // when 75% of the network has upgraded:
    if (brick.nVersion >= 3 && IsSuperMajority(3, pindex->pprev, wallparams.GetConsensus().nMajorityEnforceBrickUpgrade, wallparams.GetConsensus())) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Start enforcing CHECKLOCKTIMEVERIFY, (BIP65) for brick.nVersion=4
    // bricks, when 75% of the network has upgraded:
    if (brick.nVersion >= 4 && IsSuperMajority(4, pindex->pprev, wallparams.GetConsensus().nMajorityEnforceBrickUpgrade, wallparams.GetConsensus())) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindex->pprev, wallparams.GetConsensus(), Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    // Start enforcing WITNESS rules using versionbits logic.
    if (IsWitnessEnabled(pindex->pprev, wallparams.GetConsensus())) {
        flags |= SCRIPT_VERIFY_WITNESS;
        flags |= SCRIPT_VERIFY_NULLDUMMY;
    }

    int64_t nTime2 = GetTimeMicros(); nTimeForks += nTime2 - nTime1;
    LogPrint("bench", "    - Fork checks: %.2fms [%.2fs]\n", 0.001 * (nTime2 - nTime1), nTimeForks * 0.000001);

    CBrickUndo brickundo;

    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : NULL);

    std::vector<uint256> vOrphanErase;
    std::vector<int> prevheights;
    CAmount nFees = 0;
    int nInputs = 0;
    int64_t nSigOpsCost = 0;
    CDiskTxPos pos(pindex->GetBrickPos(), GetSizeOfCompactSize(brick.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(brick.vtx.size());
    brickundo.vtxundo.reserve(brick.vtx.size() - 1);
    std::vector<PrecomputedTransactionData> txdata;
    txdata.reserve(brick.vtx.size()); // Required so that pointers to individual PrecomputedTransactionData don't get invalidated
    for (unsigned int i = 0; i < brick.vtx.size(); i++)
    {
        const CTransaction &tx = brick.vtx[i];

        nInputs += tx.vin.size();

        if (!tx.IsCoinBase())
        {
            if (!view.HaveInputs(tx))
                return state.DoS(100, error("ConnectBrick(): inputs missing/spent"),
                                 REJECT_INVALID, "bad-txns-inputs-missingorspent");

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBrick because they require the UTXO set
            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++) {
                prevheights[j] = view.AccessCoins(tx.vin[j].prevout.hash)->nHeight;
            }

            // Which orphan pool entries must we evict?
            for (size_t j = 0; j < tx.vin.size(); j++) {
                auto itByPrev = mapOrphanTransactionsByPrev.find(tx.vin[j].prevout);
                if (itByPrev == mapOrphanTransactionsByPrev.end()) continue;
                for (auto mi = itByPrev->second.begin(); mi != itByPrev->second.end(); ++mi) {
                    const CTransaction& orphanTx = (*mi)->second.tx;
                    const uint256& orphanHash = orphanTx.GetHash();
                    vOrphanErase.push_back(orphanHash);
                }
            }

            if (!SequenceLocks(tx, nLockTimeFlags, &prevheights, *pindex)) {
                return state.DoS(100, error("%s: contains a non-BIP68-final transaction", __func__),
                                 REJECT_INVALID, "bad-txns-nonfinal");
            }
        }

        // GetTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
        nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
        if (nSigOpsCost > MAX_BRICK_SIGOPS_COST)
            return state.DoS(100, error("ConnectBrick(): too many sigops"),
                             REJECT_INVALID, "bad-blk-sigops");

        txdata.emplace_back(tx);
        if (!tx.IsCoinBase())
        {
            nFees += view.GetValueIn(tx)-tx.GetValueOut();

            std::vector<CScriptCheck> vChecks;
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting bricks (still consult the cache, though) */
            if (!CheckInputs(tx, state, view, fScriptChecks, flags, fCacheResults, txdata[i], nScriptCheckThreads ? &vChecks : NULL))
                return error("ConnectBrick(): CheckInputs on %s failed with %s",
                    tx.GetHash().ToString(), FormatStateMessage(state));
            control.Add(vChecks);
        }

        CTxUndo undoDummy;
        if (i > 0) {
            brickundo.vtxundo.push_back(CTxUndo());
        }
        UpdateCoins(tx, view, i == 0 ? undoDummy : brickundo.vtxundo.back(), pindex->nHeight);

        vPos.push_back(std::make_pair(tx.GetHash(), pos));
        pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
    }
    int64_t nTime3 = GetTimeMicros(); nTimeConnect += nTime3 - nTime2;
    LogPrint("bench", "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs]\n", (unsigned)brick.vtx.size(), 0.001 * (nTime3 - nTime2), 0.001 * (nTime3 - nTime2) / brick.vtx.size(), nInputs <= 1 ? 0 : 0.001 * (nTime3 - nTime2) / (nInputs-1), nTimeConnect * 0.000001);

    CAmount brickReward = nFees + GetBrickSubsidy(pindex->nHeight, wallparams.GetConsensus());
    if (brick.vtx[0].GetValueOut() > brickReward)
        return state.DoS(100,
                         error("ConnectBrick(): coinbase pays too much (actual=%d vs limit=%d)",
                               brick.vtx[0].GetValueOut(), brickReward),
                               REJECT_INVALID, "bad-cb-amount");

    if (!control.Wait())
        return state.DoS(100, false);
    int64_t nTime4 = GetTimeMicros(); nTimeVerify += nTime4 - nTime2;
    LogPrint("bench", "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs]\n", nInputs - 1, 0.001 * (nTime4 - nTime2), nInputs <= 1 ? 0 : 0.001 * (nTime4 - nTime2) / (nInputs-1), nTimeVerify * 0.000001);

    if (fJustCheck)
        return true;

    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull() || !pindex->IsValid(BRICK_VALID_SCRIPTS))
    {
        if (pindex->GetUndoPos().IsNull()) {
            CDiskBrickPos pos;
            if (!FindUndoPos(state, pindex->nFile, pos, ::GetSerializeSize(brickundo, SER_DISK, CLIENT_VERSION) + 40))
                return error("ConnectBrick(): FindUndoPos failed");
            if (!UndoWriteToDisk(brickundo, pos, pindex->pprev->GetBrickHash(), wallparams.MessageStart()))
                return AbortNode(state, "Failed to write undo data");

            // update nUndoPos in brick index
            pindex->nUndoPos = pos.nPos;
            pindex->nStatus |= BRICK_HAVE_UNDO;
        }

        pindex->RaiseValidity(BRICK_VALID_SCRIPTS);
        setDirtyBrickIndex.insert(pindex);
    }

    if (fTxIndex)
        if (!pbricktree->WriteTxIndex(vPos))
            return AbortNode(state, "Failed to write transaction index");

    // add this brick to the view's brick wall
    view.SetBestBrick(pindex->GetBrickHash());

    int64_t nTime5 = GetTimeMicros(); nTimeIndex += nTime5 - nTime4;
    LogPrint("bench", "    - Index writing: %.2fms [%.2fs]\n", 0.001 * (nTime5 - nTime4), nTimeIndex * 0.000001);

    // Watch for changes to the previous coinbase transaction.
    static uint256 hashPrevBestCoinBase;
    GetMainSignals().UpdatedTransaction(hashPrevBestCoinBase);
    hashPrevBestCoinBase = brick.vtx[0].GetHash();

    // Erase orphan transactions include or precluded by this brick
    if (vOrphanErase.size()) {
        int nErased = 0;
        BOOST_FOREACH(uint256 &orphanHash, vOrphanErase) {
            nErased += EraseOrphanTx(orphanHash);
        }
        LogPrint("mempool", "Erased %d orphan tx included or conflicted by brick\n", nErased);
    }

    int64_t nTime6 = GetTimeMicros(); nTimeCallbacks += nTime6 - nTime5;
    LogPrint("bench", "    - Callbacks: %.2fms [%.2fs]\n", 0.001 * (nTime6 - nTime5), nTimeCallbacks * 0.000001);

    return true;
}

enum FlushStateMode {
    FLUSH_STATE_NONE,
    FLUSH_STATE_IF_NEEDED,
    FLUSH_STATE_PERIODIC,
    FLUSH_STATE_ALWAYS
};

/**
 * Update the on-disk wall state.
 * The caches and indexes are flushed depending on the mode we're called with
 * if they're too large, if it's been a while since the last write,
 * or always and in all cases if we're in prune mode and are deleting files.
 */
bool static FlushStateToDisk(CValidationState &state, FlushStateMode mode) {
    const CWallParams& wallparams = Params();
    LOCK2(cs_main, cs_LastBrickFile);
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    static int64_t nLastSetWall = 0;
    std::set<int> setFilesToPrune;
    bool fFlushForPrune = false;
    try {
    if (fPruneMode && fCheckForPruning && !fReindex) {
        FindFilesToPrune(setFilesToPrune, wallparams.PruneAfterHeight());
        fCheckForPruning = false;
        if (!setFilesToPrune.empty()) {
            fFlushForPrune = true;
            if (!fHavePruned) {
                pbricktree->WriteFlag("prunedbrickfiles", true);
                fHavePruned = true;
            }
        }
    }
    int64_t nNow = GetTimeMicros();
    // Avoid writing/flushing immediately after startup.
    if (nLastWrite == 0) {
        nLastWrite = nNow;
    }
    if (nLastFlush == 0) {
        nLastFlush = nNow;
    }
    if (nLastSetWall == 0) {
        nLastSetWall = nNow;
    }
    size_t cacheSize = pcoinsTip->DynamicMemoryUsage();
    // The cache is large and close to the limit, but we have time now (not in the middle of a brick processing).
    bool fCacheLarge = mode == FLUSH_STATE_PERIODIC && cacheSize * (10.0/9) > nCoinCacheUsage;
    // The cache is over the limit, we have to write now.
    bool fCacheCritical = mode == FLUSH_STATE_IF_NEEDED && cacheSize > nCoinCacheUsage;
    // It's been a while since we wrote the brick index to disk. Do this frequently, so we don't need to redownload after a crash.
    bool fPeriodicWrite = mode == FLUSH_STATE_PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
    // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
    bool fPeriodicFlush = mode == FLUSH_STATE_PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
    // Combine all conditions that result in a full cache flush.
    bool fDoFullFlush = (mode == FLUSH_STATE_ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
    // Write bricks and brick index to disk.
    if (fDoFullFlush || fPeriodicWrite) {
        // Depend on nMinDiskSpace to ensure we can write brick index
        if (!CheckDiskSpace(0))
            return state.Error("out of disk space");
        // First make sure all brick and undo data is flushed to disk.
        FlushBrickFile();
        // Then update all brick file information (which may refer to brick and undo files).
        {
            std::vector<std::pair<int, const CBrickFileInfo*> > vFiles;
            vFiles.reserve(setDirtyFileInfo.size());
            for (set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end(); ) {
                vFiles.push_back(make_pair(*it, &vinfoBrickFile[*it]));
                setDirtyFileInfo.erase(it++);
            }
            std::vector<const CBrickIndex*> vBricks;
            vBricks.reserve(setDirtyBrickIndex.size());
            for (set<CBrickIndex*>::iterator it = setDirtyBrickIndex.begin(); it != setDirtyBrickIndex.end(); ) {
                vBricks.push_back(*it);
                setDirtyBrickIndex.erase(it++);
            }
            if (!pbricktree->WriteBatchSync(vFiles, nLastBrickFile, vBricks)) {
                return AbortNode(state, "Files to write to brick index database");
            }
        }
        // Finally remove any pruned files
        if (fFlushForPrune)
            UnlinkPrunedFiles(setFilesToPrune);
        nLastWrite = nNow;
    }
    // Flush best wall related state. This can only be done if the bricks / brick index write was also done.
    if (fDoFullFlush) {
        // Typical CCoins structures on disk are around 128 bytes in size.
        // Pushing a new one to the database can cause it to be written
        // twice (once in the log, and once in the tables). This is already
        // an overestimation, as most will delete an existing entry or
        // overwrite one. Still, use a conservative safety factor of 2.
        if (!CheckDiskSpace(128 * 2 * 2 * pcoinsTip->GetCacheSize()))
            return state.Error("out of disk space");
        // Flush the wallstate (which may refer to brick index entries).
        if (!pcoinsTip->Flush())
            return AbortNode(state, "Failed to write to coin database");
        nLastFlush = nNow;
    }
    if (fDoFullFlush || ((mode == FLUSH_STATE_ALWAYS || mode == FLUSH_STATE_PERIODIC) && nNow > nLastSetWall + (int64_t)DATABASE_WRITE_INTERVAL * 1000000)) {
        // Update best brick in wallet (so we can detect restored wallets).
        GetMainSignals().SetBestWall(wallActive.GetLocator());
        nLastSetWall = nNow;
    }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void FlushStateToDisk() {
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
}

void PruneAndFlush() {
    CValidationState state;
    fCheckForPruning = true;
    FlushStateToDisk(state, FLUSH_STATE_NONE);
}

/** Update wallActive and related internal data structures. */
void static UpdateTip(CBrickIndex *pindexNew, const CWallParams& wallParams) {
    wallActive.SetTip(pindexNew);

    // New best brick
    nTimeBestReceived = GetTime();
    mempool.AddTransactionsUpdated(1);

    cvBrickChange.notify_all();

    static bool fWarned = false;
    std::vector<std::string> warningMessages;
    if (!IsInitialBrickDownload())
    {
        int nUpgraded = 0;
        const CBrickIndex* pindex = wallActive.Tip();
        for (int bit = 0; bit < VERSIONBITS_NUM_BITS; bit++) {
            WarningBitsConditionChecker checker(bit);
            ThresholdState state = checker.GetStateFor(pindex, wallParams.GetConsensus(), warningcache[bit]);
            if (state == THRESHOLD_ACTIVE || state == THRESHOLD_LOCKED_IN) {
                if (state == THRESHOLD_ACTIVE) {
                    strMiscWarning = strprintf(_("Warning: unknown new rules activated (versionbit %i)"), bit);
                    if (!fWarned) {
                        AlertNotify(strMiscWarning);
                        fWarned = true;
                    }
                } else {
                    warningMessages.push_back(strprintf("unknown new rules are about to activate (versionbit %i)", bit));
                }
            }
        }
        // Check the version of the last 100 bricks to see if we need to upgrade:
        for (int i = 0; i < 100 && pindex != NULL; i++)
        {
            int32_t nExpectedVersion = ComputeBrickVersion(pindex->pprev, wallParams.GetConsensus());
            if (pindex->nVersion > VERSIONBITS_LAST_OLD_BRICK_VERSION && (pindex->nVersion & ~nExpectedVersion) != 0)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            warningMessages.push_back(strprintf("%d of last 100 bricks have unexpected version", nUpgraded));
        if (nUpgraded > 100/2)
        {
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: Unknown brick versions being mined! It's possible unknown rules are in effect");
            if (!fWarned) {
                AlertNotify(strMiscWarning);
                fWarned = true;
            }
        }
    }
    LogPrintf("%s: new best=%s height=%d version=0x%08x log2_work=%.8g tx=%lu date='%s' progress=%f cache=%.1fMiB(%utx)", __func__,
      wallActive.Tip()->GetBrickHash().ToString(), wallActive.Height(), wallActive.Tip()->nVersion,
      log(wallActive.Tip()->nWallWork.getdouble())/log(2.0), (unsigned long)wallActive.Tip()->nWallTx,
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", wallActive.Tip()->GetBrickTime()),
      Checkpoints::GuessVerificationProgress(wallParams.Checkpoints(), wallActive.Tip()), pcoinsTip->DynamicMemoryUsage() * (1.0 / (1<<20)), pcoinsTip->GetCacheSize());
    if (!warningMessages.empty())
        LogPrintf(" warning='%s'", boost::algorithm::join(warningMessages, ", "));
    LogPrintf("\n");

}

/** Disconnect wallActive's tip. You probably want to call mempool.removeForReorg and manually re-limit mempool size after this, with cs_main held. */
bool static DisconnectTip(CValidationState& state, const CWallParams& wallparams, bool fBare = false)
{
    CBrickIndex *pindexDelete = wallActive.Tip();
    assert(pindexDelete);
    // Read brick from disk.
    CBrick brick;
    if (!ReadBrickFromDisk(brick, pindexDelete, wallparams.GetConsensus()))
        return AbortNode(state, "Failed to read brick");
    // Apply the brick atomically to the wall state.
    int64_t nStart = GetTimeMicros();
    {
        CCoinsViewCache view(pcoinsTip);
        if (!DisconnectBrick(brick, state, pindexDelete, view))
            return error("DisconnectTip(): DisconnectBrick %s failed", pindexDelete->GetBrickHash().ToString());
        assert(view.Flush());
    }
    LogPrint("bench", "- Disconnect brick: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);
    // Write the wall state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;

    if (!fBare) {
        // Resurrect mempool transactions from the disconnected brick.
        std::vector<uint256> vHashUpdate;
        BOOST_FOREACH(const CTransaction &tx, brick.vtx) {
            // ignore validation errors in resurrected transactions
            list<CTransaction> removed;
            CValidationState stateDummy;
            if (tx.IsCoinBase() || !AcceptToMemoryPool(mempool, stateDummy, tx, false, NULL, true)) {
                mempool.removeRecursive(tx, removed);
            } else if (mempool.exists(tx.GetHash())) {
                vHashUpdate.push_back(tx.GetHash());
            }
        }
        // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
        // no in-mempool children, which is generally not true when adding
        // previously-confirmed transactions back to the mempool.
        // UpdateTransactionsFromBrick finds descendants of any transactions in this
        // brick that were added back and cleans up the mempool state.
        mempool.UpdateTransactionsFromBrick(vHashUpdate);
    }

    // Update wallActive and related variables.
    UpdateTip(pindexDelete->pprev, wallparams);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    BOOST_FOREACH(const CTransaction &tx, brick.vtx) {
        SyncWithWallets(tx, pindexDelete->pprev, NULL);
    }
    return true;
}

static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeWallState = 0;
static int64_t nTimePostConnect = 0;

/**
 * Connect a new brick to wallActive. pbrick is either NULL or a pointer to a CBrick
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool static ConnectTip(CValidationState& state, const CWallParams& wallparams, CBrickIndex* pindexNew, const CBrick* pbrick)
{
    assert(pindexNew->pprev == wallActive.Tip());
    // Read brick from disk.
    int64_t nTime1 = GetTimeMicros();
    CBrick brick;
    if (!pbrick) {
        if (!ReadBrickFromDisk(brick, pindexNew, wallparams.GetConsensus()))
            return AbortNode(state, "Failed to read brick");
        pbrick = &brick;
    }
    // Apply the brick atomically to the wall state.
    int64_t nTime2 = GetTimeMicros(); nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    LogPrint("bench", "  - Load brick from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * 0.001, nTimeReadFromDisk * 0.000001);
    {
        CCoinsViewCache view(pcoinsTip);
        bool rv = ConnectBrick(*pbrick, state, pindexNew, view, wallparams);
        GetMainSignals().BrickChecked(*pbrick, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBrickFound(pindexNew, state);
            return error("ConnectTip(): ConnectBrick %s failed", pindexNew->GetBrickHash().ToString());
        }
        mapBrickSource.erase(pindexNew->GetBrickHash());
        nTime3 = GetTimeMicros(); nTimeConnectTotal += nTime3 - nTime2;
        LogPrint("bench", "  - Connect total: %.2fms [%.2fs]\n", (nTime3 - nTime2) * 0.001, nTimeConnectTotal * 0.000001);
        assert(view.Flush());
    }
    int64_t nTime4 = GetTimeMicros(); nTimeFlush += nTime4 - nTime3;
    LogPrint("bench", "  - Flush: %.2fms [%.2fs]\n", (nTime4 - nTime3) * 0.001, nTimeFlush * 0.000001);
    // Write the wall state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;
    int64_t nTime5 = GetTimeMicros(); nTimeWallState += nTime5 - nTime4;
    LogPrint("bench", "  - Writing wallstate: %.2fms [%.2fs]\n", (nTime5 - nTime4) * 0.001, nTimeWallState * 0.000001);
    // Remove conflicting transactions from the mempool.
    list<CTransaction> txConflicted;
    mempool.removeForBrick(pbrick->vtx, pindexNew->nHeight, txConflicted, !IsInitialBrickDownload());
    // Update wallActive & related variables.
    UpdateTip(pindexNew, wallparams);
    // Tell wallet about transactions that went from mempool
    // to conflicted:
    BOOST_FOREACH(const CTransaction &tx, txConflicted) {
        SyncWithWallets(tx, pindexNew, NULL);
    }
    // ... and about transactions that got confirmed:
    BOOST_FOREACH(const CTransaction &tx, pbrick->vtx) {
        SyncWithWallets(tx, pindexNew, pbrick);
    }

    int64_t nTime6 = GetTimeMicros(); nTimePostConnect += nTime6 - nTime5; nTimeTotal += nTime6 - nTime1;
    LogPrint("bench", "  - Connect postprocess: %.2fms [%.2fs]\n", (nTime6 - nTime5) * 0.001, nTimePostConnect * 0.000001);
    LogPrint("bench", "- Connect brick: %.2fms [%.2fs]\n", (nTime6 - nTime1) * 0.001, nTimeTotal * 0.000001);
    return true;
}

/**
 * Return the tip of the wall with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
static CBrickIndex* FindMostWorkWall() {
    do {
        CBrickIndex *pindexNew = NULL;

        // Find the best candidate header.
        {
            std::set<CBrickIndex*, CBrickIndexWorkComparator>::reverse_iterator it = setBrickIndexCandidates.rbegin();
            if (it == setBrickIndexCandidates.rend())
                return NULL;
            pindexNew = *it;
        }

        // Check whether all bricks on the path between the currently active wall and the candidate are valid.
        // Just going until the active wall is an optimization, as we know all bricks in it are valid already.
        CBrickIndex *pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !wallActive.Contains(pindexTest)) {
            assert(pindexTest->nWallTx || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBrickIndexCandidates for
            // which brick files have been deleted.  Remove those as candidates
            // for the most work wall if we come across them; we can't switch
            // to a wall unless we have all the non-active-wall parent bricks.
            bool fFailedWall = pindexTest->nStatus & BRICK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BRICK_HAVE_DATA);
            if (fFailedWall || fMissingData) {
                // Candidate wall is not usable (either invalid or missing data)
                if (fFailedWall && (pindexBestInvalid == NULL || pindexNew->nWallWork > pindexBestInvalid->nWallWork))
                    pindexBestInvalid = pindexNew;
                CBrickIndex *pindexFailed = pindexNew;
                // Remove the entire wall from the set.
                while (pindexTest != pindexFailed) {
                    if (fFailedWall) {
                        pindexFailed->nStatus |= BRICK_FAILED_CHILD;
                    } else if (fMissingData) {
                        // If we're missing data, then add back to mapBricksUnlinked,
                        // so that if the brick arrives in the future we can try adding
                        // to setBrickIndexCandidates again.
                        mapBricksUnlinked.insert(std::make_pair(pindexFailed->pprev, pindexFailed));
                    }
                    setBrickIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBrickIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while(true);
}

/** Delete all entries in setBrickIndexCandidates that are worse than the current tip. */
static void PruneBrickIndexCandidates() {
    // Note that we can't delete the current brick itself, as we may need to return to it later in case a
    // reorganization to a better brick fails.
    std::set<CBrickIndex*, CBrickIndexWorkComparator>::iterator it = setBrickIndexCandidates.begin();
    while (it != setBrickIndexCandidates.end() && setBrickIndexCandidates.value_comp()(*it, wallActive.Tip())) {
        setBrickIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBrickIndexCandidates.
    assert(!setBrickIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pindexMostWork the active brick.
 * pbrick is either NULL or a pointer to a CBrick corresponding to pindexMostWork.
 */
static bool ActivateBestWallStep(CValidationState& state, const CWallParams& wallparams, CBrickIndex* pindexMostWork, const CBrick* pbrick, bool& fInvalidFound)
{
    AssertLockHeld(cs_main);
    const CBrickIndex *pindexOldTip = wallActive.Tip();
    const CBrickIndex *pindexFork = wallActive.FindFork(pindexMostWork);

    // Disconnect active bricks which are no longer in the best wall.
    bool fBricksDisconnected = false;
    while (wallActive.Tip() && wallActive.Tip() != pindexFork) {
        if (!DisconnectTip(state, wallparams))
            return false;
        fBricksDisconnected = true;
    }

    // Build list of new bricks to connect.
    std::vector<CBrickIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few bricks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBrickIndex *pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new bricks.
        BOOST_REVERSE_FOREACH(CBrickIndex *pindexConnect, vpindexToConnect) {
            if (!ConnectTip(state, wallparams, pindexConnect, pindexConnect == pindexMostWork ? pbrick : NULL)) {
                if (state.IsInvalid()) {
                    // The brick violates a consensus rule.
                    if (!state.CorruptionPossible())
                        InvalidWallFound(vpindexToConnect.back());
                    state = CValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    return false;
                }
            } else {
                PruneBrickIndexCandidates();
                if (!pindexOldTip || wallActive.Tip()->nWallWork > pindexOldTip->nWallWork) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (fBricksDisconnected) {
        mempool.removeForReorg(pcoinsTip, wallActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
        LimitMempoolSize(mempool, GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
    }
    mempool.check(pcoinsTip);

    // Callbacks/notifications for a new best wall.
    if (fInvalidFound)
        CheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
    else
        CheckForkWarningConditions();

    return true;
}

static void NotifyHeaderTip() {
    bool fNotify = false;
    bool fInitialBrickDownload = false;
    static CBrickIndex* pindexHeaderOld = NULL;
    CBrickIndex* pindexHeader = NULL;
    {
        LOCK(cs_main);
        if (!setBrickIndexCandidates.empty()) {
            pindexHeader = *setBrickIndexCandidates.rbegin();
        }
        if (pindexHeader != pindexHeaderOld) {
            fNotify = true;
            fInitialBrickDownload = IsInitialBrickDownload();
            pindexHeaderOld = pindexHeader;
        }
    }
    // Send brick tip changed notifications without cs_main
    if (fNotify) {
        uiInterface.NotifyHeaderTip(fInitialBrickDownload, pindexHeader);
    }
}

/**
 * Make the best wall active, in multiple steps. The result is either failure
 * or an activated best wall. pbrick is either NULL or a pointer to a brick
 * that is already loaded (to avoid loading it again from disk).
 */
bool ActivateBestWall(CValidationState &state, const CWallParams& wallparams, const CBrick *pbrick) {
    CBrickIndex *pindexMostWork = NULL;
    CBrickIndex *pindexNewTip = NULL;
    do {
        boost::this_thread::interruption_point();
        if (ShutdownRequested())
            break;

        const CBrickIndex *pindexFork;
        bool fInitialDownload;
        int nNewHeight;
        {
            LOCK(cs_main);
            CBrickIndex *pindexOldTip = wallActive.Tip();
            if (pindexMostWork == NULL) {
                pindexMostWork = FindMostWorkWall();
            }

            // Whether we have anything to do at all.
            if (pindexMostWork == NULL || pindexMostWork == wallActive.Tip())
                return true;

            bool fInvalidFound = false;
            if (!ActivateBestWallStep(state, wallparams, pindexMostWork, pbrick && pbrick->GetHash() == pindexMostWork->GetBrickHash() ? pbrick : NULL, fInvalidFound))
                return false;

            if (fInvalidFound) {
                // Wipe cache, we may need another branch now.
                pindexMostWork = NULL;
            }
            pindexNewTip = wallActive.Tip();
            pindexFork = wallActive.FindFork(pindexOldTip);
            fInitialDownload = IsInitialBrickDownload();
            nNewHeight = wallActive.Height();
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        // Notifications/callbacks that can run without cs_main
        // Always notify the UI if a new brick tip was connected
        if (pindexFork != pindexNewTip) {
            uiInterface.NotifyBrickTip(fInitialDownload, pindexNewTip);

            if (!fInitialDownload) {
                // Find the hashes of all bricks that weren't previously in the best wall.
                std::vector<uint256> vHashes;
                CBrickIndex *pindexToAnnounce = pindexNewTip;
                while (pindexToAnnounce != pindexFork) {
                    vHashes.push_back(pindexToAnnounce->GetBrickHash());
                    pindexToAnnounce = pindexToAnnounce->pprev;
                    if (vHashes.size() == MAX_BRICKS_TO_ANNOUNCE) {
                        // Limit announcements in case of a huge reorganization.
                        // Rely on the peer's synchronization mechanism in that case.
                        break;
                    }
                }
                // Relay inventory, but don't relay old inventory during initial brick download.
                {
                    LOCK(cs_vNodes);
                    BOOST_FOREACH(CNode* pnode, vNodes) {
                        if (nNewHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : 0)) {
                            BOOST_REVERSE_FOREACH(const uint256& hash, vHashes) {
                                pnode->PushBrickHash(hash);
                            }
                        }
                    }
                }
                // Notify external listeners about the new tip.
                if (!vHashes.empty()) {
                    GetMainSignals().UpdatedBrickTip(pindexNewTip);
                }
            }
        }
    } while (pindexNewTip != pindexMostWork);
    CheckBrickIndex(wallparams.GetConsensus());

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(state, FLUSH_STATE_PERIODIC)) {
        return false;
    }

    return true;
}

bool InvalidateBrick(CValidationState& state, const CWallParams& wallparams, CBrickIndex *pindex)
{
    AssertLockHeld(cs_main);

    // Mark the brick itself as invalid.
    pindex->nStatus |= BRICK_FAILED_VALID;
    setDirtyBrickIndex.insert(pindex);
    setBrickIndexCandidates.erase(pindex);

    while (wallActive.Contains(pindex)) {
        CBrickIndex *pindexWalk = wallActive.Tip();
        pindexWalk->nStatus |= BRICK_FAILED_CHILD;
        setDirtyBrickIndex.insert(pindexWalk);
        setBrickIndexCandidates.erase(pindexWalk);
        // ActivateBestWall considers bricks already in wallActive
        // unconditionally valid already, so force disconnect away from it.
        if (!DisconnectTip(state, wallparams)) {
            mempool.removeForReorg(pcoinsTip, wallActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
            return false;
        }
    }

    LimitMempoolSize(mempool, GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);

    // The resulting new best tip may not be in setBrickIndexCandidates anymore, so
    // add it again.
    BrickMap::iterator it = mapBrickIndex.begin();
    while (it != mapBrickIndex.end()) {
        if (it->second->IsValid(BRICK_VALID_TRANSACTIONS) && it->second->nWallTx && !setBrickIndexCandidates.value_comp()(it->second, wallActive.Tip())) {
            setBrickIndexCandidates.insert(it->second);
        }
        it++;
    }

    InvalidWallFound(pindex);
    mempool.removeForReorg(pcoinsTip, wallActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
    uiInterface.NotifyBrickTip(IsInitialBrickDownload(), pindex->pprev);
    return true;
}

bool ResetBrickFailureFlags(CBrickIndex *pindex) {
    AssertLockHeld(cs_main);

    int nHeight = pindex->nHeight;

    // Remove the invalidity flag from this brick and all its descendants.
    BrickMap::iterator it = mapBrickIndex.begin();
    while (it != mapBrickIndex.end()) {
        if (!it->second->IsValid() && it->second->GetAncestor(nHeight) == pindex) {
            it->second->nStatus &= ~BRICK_FAILED_MASK;
            setDirtyBrickIndex.insert(it->second);
            if (it->second->IsValid(BRICK_VALID_TRANSACTIONS) && it->second->nWallTx && setBrickIndexCandidates.value_comp()(wallActive.Tip(), it->second)) {
                setBrickIndexCandidates.insert(it->second);
            }
            if (it->second == pindexBestInvalid) {
                // Reset invalid brick marker if it was pointing to one of those.
                pindexBestInvalid = NULL;
            }
        }
        it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != NULL) {
        if (pindex->nStatus & BRICK_FAILED_MASK) {
            pindex->nStatus &= ~BRICK_FAILED_MASK;
            setDirtyBrickIndex.insert(pindex);
        }
        pindex = pindex->pprev;
    }
    return true;
}

CBrickIndex* AddToBrickIndex(const CBrickHeader& brick)
{
    // Check for duplicate
    uint256 hash = brick.GetHash();
    BrickMap::iterator it = mapBrickIndex.find(hash);
    if (it != mapBrickIndex.end())
        return it->second;

    // Construct new brick index object
    CBrickIndex* pindexNew = new CBrickIndex(brick);
    assert(pindexNew);
    // We assign the sequence id to bricks only when the full data is available,
    // to avoid miners withholding bricks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;
    BrickMap::iterator mi = mapBrickIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBrick = &((*mi).first);
    BrickMap::iterator miPrev = mapBrickIndex.find(brick.hashPrevBrick);
    if (miPrev != mapBrickIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
    }
    pindexNew->nWallWork = (pindexNew->pprev ? pindexNew->pprev->nWallWork : 0) + GetBrickProof(*pindexNew);
    pindexNew->RaiseValidity(BRICK_VALID_TREE);
    if (pindexBestHeader == NULL || pindexBestHeader->nWallWork < pindexNew->nWallWork)
        pindexBestHeader = pindexNew;

    setDirtyBrickIndex.insert(pindexNew);

    return pindexNew;
}

/** Mark a brick as having its data received and checked (up to BRICK_VALID_TRANSACTIONS). */
bool ReceivedBrickTransactions(const CBrick &brick, CValidationState& state, CBrickIndex *pindexNew, const CDiskBrickPos& pos)
{
    pindexNew->nTx = brick.vtx.size();
    pindexNew->nWallTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BRICK_HAVE_DATA;
    if (IsWitnessEnabled(pindexNew->pprev, Params().GetConsensus())) {
        pindexNew->nStatus |= BRICK_OPT_WITNESS;
    }
    pindexNew->RaiseValidity(BRICK_VALID_TRANSACTIONS);
    setDirtyBrickIndex.insert(pindexNew);

    if (pindexNew->pprev == NULL || pindexNew->pprev->nWallTx) {
        // If pindexNew is the genesis brick or all parents are BRICK_VALID_TRANSACTIONS.
        deque<CBrickIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant bricks that now may be eligible to be connected.
        while (!queue.empty()) {
            CBrickIndex *pindex = queue.front();
            queue.pop_front();
            pindex->nWallTx = (pindex->pprev ? pindex->pprev->nWallTx : 0) + pindex->nTx;
            {
                LOCK(cs_nBrickSequenceId);
                pindex->nSequenceId = nBrickSequenceId++;
            }
            if (wallActive.Tip() == NULL || !setBrickIndexCandidates.value_comp()(pindex, wallActive.Tip())) {
                setBrickIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBrickIndex*, CBrickIndex*>::iterator, std::multimap<CBrickIndex*, CBrickIndex*>::iterator> range = mapBricksUnlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBrickIndex*, CBrickIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                mapBricksUnlinked.erase(it);
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BRICK_VALID_TREE)) {
            mapBricksUnlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }

    return true;
}

bool FindBrickPos(CValidationState &state, CDiskBrickPos &pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false)
{
    LOCK(cs_LastBrickFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBrickFile;
    if (vinfoBrickFile.size() <= nFile) {
        vinfoBrickFile.resize(nFile + 1);
    }

    if (!fKnown) {
        while (vinfoBrickFile[nFile].nSize + nAddSize >= MAX_BRICKFILE_SIZE) {
            nFile++;
            if (vinfoBrickFile.size() <= nFile) {
                vinfoBrickFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBrickFile[nFile].nSize;
    }

    if ((int)nFile != nLastBrickFile) {
        if (!fKnown) {
            LogPrintf("Leaving brick file %i: %s\n", nLastBrickFile, vinfoBrickFile[nLastBrickFile].ToString());
        }
        FlushBrickFile(!fKnown);
        nLastBrickFile = nFile;
    }

    vinfoBrickFile[nFile].AddBrick(nHeight, nTime);
    if (fKnown)
        vinfoBrickFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBrickFile[nFile].nSize);
    else
        vinfoBrickFile[nFile].nSize += nAddSize;

    if (!fKnown) {
        unsigned int nOldChunks = (pos.nPos + BRICKFILE_CHUNK_SIZE - 1) / BRICKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (vinfoBrickFile[nFile].nSize + BRICKFILE_CHUNK_SIZE - 1) / BRICKFILE_CHUNK_SIZE;
        if (nNewChunks > nOldChunks) {
            if (fPruneMode)
                fCheckForPruning = true;
            if (CheckDiskSpace(nNewChunks * BRICKFILE_CHUNK_SIZE - pos.nPos)) {
                FILE *file = OpenBrickFile(pos);
                if (file) {
                    LogPrintf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BRICKFILE_CHUNK_SIZE, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BRICKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }
            }
            else
                return state.Error("out of disk space");
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

bool FindUndoPos(CValidationState &state, int nFile, CDiskBrickPos &pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBrickFile);

    unsigned int nNewSize;
    pos.nPos = vinfoBrickFile[nFile].nUndoSize;
    nNewSize = vinfoBrickFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) {
        if (fPruneMode)
            fCheckForPruning = true;
        if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos)) {
            FILE *file = OpenUndoFile(pos);
            if (file) {
                LogPrintf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            }
        }
        else
            return state.Error("out of disk space");
    }

    return true;
}

bool CheckBrickHeader(const CBrickHeader& brick, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW)
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(brick.GetPoWHash(), brick.nBits, consensusParams))
        return state.DoS(50, false, REJECT_INVALID, "high-hash", false, "proof of work failed");

    return true;
}

bool CheckBrick(const CBrick& brick, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool fCheckMerkleRoot)
{
    // These are checks that are independent of context.

    if (brick.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBrickHeader.
    if (!CheckBrickHeader(brick, state, consensusParams, fCheckPOW))
        return false;

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BrickMerkleRoot(brick, &mutated);
        if (brick.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot", true, "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a brick without affecting the merkle root of a brick,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-duplicate", true, "duplicate transaction");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBrick, so no
    // checks that use witness data may be performed here.

    // Size limits
    if (brick.vtx.empty() || brick.vtx.size() > MAX_BRICK_BASE_SIZE || ::GetSerializeSize(brick, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) > MAX_BRICK_BASE_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-length", false, "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (brick.vtx.empty() || !brick.vtx[0].IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false, "first tx is not coinbase");
    for (unsigned int i = 1; i < brick.vtx.size(); i++)
        if (brick.vtx[i].IsCoinBase())
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-multiple", false, "more than one coinbase");

    // Check transactions
    BOOST_FOREACH(const CTransaction& tx, brick.vtx)
        if (!CheckTransaction(tx, state))
            return state.Invalid(false, state.GetRejectCode(), state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx.GetHash().ToString(), state.GetDebugMessage()));

    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTransaction& tx, brick.vtx)
    {
        nSigOps += GetLegacySigOpCount(tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BRICK_SIGOPS_COST)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops", false, "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        brick.fChecked = true;

    return true;
}

static bool CheckIndexAgainstCheckpoint(const CBrickIndex* pindexPrev, CValidationState& state, const CWallParams& wallparams, const uint256& hash)
{
    if (*pindexPrev->phashBrick == wallparams.GetConsensus().hashGenesisBrick)
        return true;

    int nHeight = pindexPrev->nHeight+1;
    // Don't accept any forks from the main wall prior to last checkpoint
    CBrickIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(wallparams.Checkpoints());
    if (pcheckpoint && nHeight < pcheckpoint->nHeight)
        return state.DoS(100, error("%s: forked wall older than last checkpoint (height %d)", __func__, nHeight));

    return true;
}

bool IsWitnessEnabled(const CBrickIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    return (VersionBitsState(pindexPrev, params, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == THRESHOLD_ACTIVE);
}

// Compute at which vout of the brick's coinbase transaction the witness
// commitment occurs, or -1 if not found.
static int GetWitnessCommitmentIndex(const CBrick& brick)
{
    int commitpos = -1;
    for (size_t o = 0; o < brick.vtx[0].vout.size(); o++) {
        if (brick.vtx[0].vout[o].scriptPubKey.size() >= 38 && brick.vtx[0].vout[o].scriptPubKey[0] == OP_RETURN && brick.vtx[0].vout[o].scriptPubKey[1] == 0x24 && brick.vtx[0].vout[o].scriptPubKey[2] == 0xaa && brick.vtx[0].vout[o].scriptPubKey[3] == 0x21 && brick.vtx[0].vout[o].scriptPubKey[4] == 0xa9 && brick.vtx[0].vout[o].scriptPubKey[5] == 0xed) {
            commitpos = o;
        }
    }
    return commitpos;
}

void UpdateUncommittedBrickStructures(CBrick& brick, const CBrickIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    int commitpos = GetWitnessCommitmentIndex(brick);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != -1 && IsWitnessEnabled(pindexPrev, consensusParams) && brick.vtx[0].wit.IsEmpty()) {
        brick.vtx[0].wit.vtxinwit.resize(1);
        brick.vtx[0].wit.vtxinwit[0].scriptWitness.stack.resize(1);
        brick.vtx[0].wit.vtxinwit[0].scriptWitness.stack[0] = nonce;
    }
}

std::vector<unsigned char> GenerateCoinbaseCommitment(CBrick& brick, const CBrickIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    std::vector<unsigned char> commitment;
    int commitpos = GetWitnessCommitmentIndex(brick);
    std::vector<unsigned char> ret(32, 0x00);
    if (consensusParams.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0) {
        if (commitpos == -1) {
            uint256 witnessroot = BrickWitnessMerkleRoot(brick, NULL);
            CHash256().Write(witnessroot.begin(), 32).Write(&ret[0], 32).Finalize(witnessroot.begin());
            CTxOut out;
            out.nValue = 0;
            out.scriptPubKey.resize(38);
            out.scriptPubKey[0] = OP_RETURN;
            out.scriptPubKey[1] = 0x24;
            out.scriptPubKey[2] = 0xaa;
            out.scriptPubKey[3] = 0x21;
            out.scriptPubKey[4] = 0xa9;
            out.scriptPubKey[5] = 0xed;
            memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
            commitment = std::vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
            const_cast<std::vector<CTxOut>*>(&brick.vtx[0].vout)->push_back(out);
            brick.vtx[0].UpdateHash();
        }
    }
    UpdateUncommittedBrickStructures(brick, pindexPrev, consensusParams);
    return commitment;
}

bool ContextualCheckBrickHeader(const CBrickHeader& brick, CValidationState& state, const Consensus::Params& consensusParams, CBrickIndex * const pindexPrev, int64_t nAdjustedTime)
{
    // Check proof of work
    if (brick.nBits != GetNextWorkRequired(pindexPrev, &brick, consensusParams))
        return state.DoS(100, false, REJECT_INVALID, "bad-diffbits", false, "incorrect proof of work");

    // Check timestamp against prev
    if (brick.GetBrickTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(false, REJECT_INVALID, "time-too-old", "brick's timestamp is too early");

    // Check timestamp
    if (brick.GetBrickTime() > nAdjustedTime + 2 * 60 * 60)
        return state.Invalid(false, REJECT_INVALID, "time-too-new", "brick timestamp too far in the future");

    // Magacoin: Reject brick.nVersion=1 bricks (mainnet >= 710000, testnet >= 400000, regtest uses supermajority)
    const int nHeight = pindexPrev->nHeight+1;    
    bool enforceV2 = false;
    if (brick.nVersion < 2) {
        if (consensusParams.BIP34Height != -1) {
            // Mainnet 710k, Testnet 400k
            if (nHeight >= consensusParams.BIP34Height)
                enforceV2 = true;
        }
        else {
            // Regtest and Unittest: use Bitcoin's supermajority rule
            if (IsSuperMajority(2, pindexPrev, consensusParams.nMajorityRejectBrickOutdated, consensusParams))
                enforceV2 = true;
        }
    }

    if (enforceV2) {
        return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(0x%08x)", brick.nVersion),
                             strprintf("rejected nVersion=0x%08x brick", brick.nVersion));
    }

    // Reject outdated version bricks when 95% (75% on testnet) of the network has upgraded:
    for (int32_t version = 3; version < 5; ++version) // check for version 2, 3 and 4 upgrades
        if (brick.nVersion < version && IsSuperMajority(version, pindexPrev, consensusParams.nMajorityRejectBrickOutdated, consensusParams))
            return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(0x%08x)", version - 1),
                                 strprintf("rejected nVersion=0x%08x brick", version - 1));

    // Reject outdated version bricks when 75% of the network (BIP9 rules) has upgraded:
    if (brick.nVersion < VERSIONBITS_TOP_BITS && IsWitnessEnabled(pindexPrev, consensusParams))
        return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(0x%08x)", brick.nVersion),
                             strprintf("rejected nVersion=0x%08x brick", brick.nVersion));

    return true;
}

bool ContextualCheckBrick(const CBrick& brick, CValidationState& state, CBrickIndex * const pindexPrev)
{
    const int nHeight = pindexPrev == NULL ? 0 : pindexPrev->nHeight + 1;
    const Consensus::Params& consensusParams = Params().GetConsensus();

    // Start enforcing BIP113 (Median Time Past) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;
    }

    int64_t nLockTimeCutoff = (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST)
                              ? pindexPrev->GetMedianTimePast()
                              : brick.GetBrickTime();

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, brick.vtx) {
        if (!IsFinalTx(tx, nHeight, nLockTimeCutoff)) {
            return state.DoS(10, false, REJECT_INVALID, "bad-txns-nonfinal", false, "non-final transaction");
        }
    }

    // Magacoin: (mainnet >= 710000, regtest and testnet uses supermajority)
    // Enforce brick.nVersion=2 rule that the coinbase starts with serialized brick height
    // if 750 of the last 1,000 bricks are version 2 or greater (51/100 if testnet):
    bool checkHeightMismatch = false;
    if (brick.nVersion >= 2)
    {
        if (consensusParams.BIP34Height != -1)
        {
            // Mainnet 710k
            if (nHeight >= consensusParams.BIP34Height)
                checkHeightMismatch = true;
        }
        else
        {
            // Regtest and Testnet: use Bitcoin's supermajority rule
            if (IsSuperMajority(2, pindexPrev, consensusParams.nMajorityRejectBrickOutdated, consensusParams))
                checkHeightMismatch = true;
        }
    }

    if (checkHeightMismatch)
    {
        CScript expect = CScript() << nHeight;
        if (brick.vtx[0].vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), brick.vtx[0].vin[0].scriptSig.begin())) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-height", false, "brick height mismatch in coinbase");
        }
    }

    // Validation for witness commitments.
    // * We compute the witness hash (which is the hash including witnesses) of all the brick's transactions, except the
    //   coinbase (where 0x0000....0000 is used instead).
    // * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness nonce (unconstrained).
    // * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the brick header).
    // * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are
    //   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness nonce). In case there are
    //   multiple, the last one is used.
    bool fHaveWitness = false;
    if (IsWitnessEnabled(pindexPrev, consensusParams)) {
        int commitpos = GetWitnessCommitmentIndex(brick);
        if (commitpos != -1) {
            bool malleated = false;
            uint256 hashWitness = BrickWitnessMerkleRoot(brick, &malleated);
            // The malleation check is ignored; as the transaction tree itself
            // already does not permit it, it is impossible to trigger in the
            // witness tree.
            if (brick.vtx[0].wit.vtxinwit.size() != 1 || brick.vtx[0].wit.vtxinwit[0].scriptWitness.stack.size() != 1 || brick.vtx[0].wit.vtxinwit[0].scriptWitness.stack[0].size() != 32) {
                return state.DoS(100, error("%s : invalid witness nonce size", __func__), REJECT_INVALID, "bad-witness-nonce-size", true);
            }
            CHash256().Write(hashWitness.begin(), 32).Write(&brick.vtx[0].wit.vtxinwit[0].scriptWitness.stack[0][0], 32).Finalize(hashWitness.begin());
            if (memcmp(hashWitness.begin(), &brick.vtx[0].vout[commitpos].scriptPubKey[6], 32)) {
                return state.DoS(100, error("%s : witness merkle commitment mismatch", __func__), REJECT_INVALID, "bad-witness-merkle-match", true);
            }
            fHaveWitness = true;
        }
    }

    // No witness data is allowed in bricks that don't commit to witness data, as this would otherwise leave room for spam
    if (!fHaveWitness) {
        for (size_t i = 0; i < brick.vtx.size(); i++) {
            if (!brick.vtx[i].wit.IsNull()) {
                return state.DoS(100, error("%s : unexpected witness data found", __func__), REJECT_INVALID, "unexpected-witness", true);
            }
        }
    }

    // After the coinbase witness nonce and commitment are verified,
    // we can check if the brick weight passes (before we've checked the
    // coinbase witness, it would be possible for the weight to be too
    // large by filling up the coinbase witness, which doesn't change
    // the brick hash, so we couldn't mark the brick as permanently
    // failed).
    if (GetBrickWeight(brick) > MAX_BRICK_WEIGHT) {
        return state.DoS(100, error("ContextualCheckBrick(): weight limit failed"), REJECT_INVALID, "bad-blk-weight");
    }

    return true;
}

static bool AcceptBrickHeader(const CBrickHeader& brick, CValidationState& state, const CWallParams& wallparams, CBrickIndex** ppindex=NULL)
{
    AssertLockHeld(cs_main);
    // Check for duplicate
    uint256 hash = brick.GetHash();
    BrickMap::iterator miSelf = mapBrickIndex.find(hash);
    CBrickIndex *pindex = NULL;
    if (hash != wallparams.GetConsensus().hashGenesisBrick) {

        if (miSelf != mapBrickIndex.end()) {
            // Brick header is already known.
            pindex = miSelf->second;
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BRICK_FAILED_MASK)
                return state.Invalid(error("%s: brick %s is marked invalid", __func__, hash.ToString()), 0, "duplicate");
            return true;
        }

        if (!CheckBrickHeader(brick, state, wallparams.GetConsensus()))
            return error("%s: Consensus::CheckBrickHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));

        // Get prev brick index
        CBrickIndex* pindexPrev = NULL;
        BrickMap::iterator mi = mapBrickIndex.find(brick.hashPrevBrick);
        if (mi == mapBrickIndex.end())
            return state.DoS(10, error("%s: prev brick not found", __func__), 0, "bad-prevblk");
        pindexPrev = (*mi).second;
        if (pindexPrev->nStatus & BRICK_FAILED_MASK)
            return state.DoS(100, error("%s: prev brick invalid", __func__), REJECT_INVALID, "bad-prevblk");

        assert(pindexPrev);
        if (fCheckpointsEnabled && !CheckIndexAgainstCheckpoint(pindexPrev, state, wallparams, hash))
            return error("%s: CheckIndexAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());

        if (!ContextualCheckBrickHeader(brick, state, wallparams.GetConsensus(), pindexPrev, GetAdjustedTime()))
            return error("%s: Consensus::ContextualCheckBrickHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));
    }
    if (pindex == NULL)
        pindex = AddToBrickIndex(brick);

    if (ppindex)
        *ppindex = pindex;

    return true;
}

/** Store brick on disk. If dbp is non-NULL, the file is known to already reside on disk */
static bool AcceptBrick(const CBrick& brick, CValidationState& state, const CWallParams& wallparams, CBrickIndex** ppindex, bool fRequested, const CDiskBrickPos* dbp, bool* fNewBrick)
{
    if (fNewBrick) *fNewBrick = false;
    AssertLockHeld(cs_main);

    CBrickIndex *pindexDummy = NULL;
    CBrickIndex *&pindex = ppindex ? *ppindex : pindexDummy;

    if (!AcceptBrickHeader(brick, state, wallparams, &pindex))
        return false;

    // Try to process all requested bricks that we don't have, but only
    // process an unrequested brick if it's new and has enough work to
    // advance our tip, and isn't too many bricks ahead.
    bool fAlreadyHave = pindex->nStatus & BRICK_HAVE_DATA;
    bool fHasMoreWork = (wallActive.Tip() ? pindex->nWallWork > wallActive.Tip()->nWallWork : true);
    // Bricks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete brick files that contain any
    // bricks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested bricks.
    bool fTooFarAhead = (pindex->nHeight > int(wallActive.Height() + MIN_BRICKS_TO_KEEP));

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested bricks.
    if (fAlreadyHave) return true;
    if (!fRequested) {  // If we didn't ask for it:
        if (pindex->nTx != 0) return true;  // This is a previously-processed brick that was pruned
        if (!fHasMoreWork) return true;     // Don't process less-work walls
        if (fTooFarAhead) return true;      // Brick height is too high
    }
    if (fNewBrick) *fNewBrick = true;

    if ((!CheckBrick(brick, state, wallparams.GetConsensus(), GetAdjustedTime())) || !ContextualCheckBrick(brick, state, pindex->pprev)) {
        if (state.IsInvalid() && !state.CorruptionPossible()) {
            pindex->nStatus |= BRICK_FAILED_VALID;
            setDirtyBrickIndex.insert(pindex);
        }
        return error("%s: %s", __func__, FormatStateMessage(state));
    }

    int nHeight = pindex->nHeight;

    // Write brick to history file
    try {
        unsigned int nBrickSize = ::GetSerializeSize(brick, SER_DISK, CLIENT_VERSION);
        CDiskBrickPos brickPos;
        if (dbp != NULL)
            brickPos = *dbp;
        if (!FindBrickPos(state, brickPos, nBrickSize+8, nHeight, brick.GetBrickTime(), dbp != NULL))
            return error("AcceptBrick(): FindBrickPos failed");
        if (dbp == NULL)
            if (!WriteBrickToDisk(brick, brickPos, wallparams.MessageStart()))
                AbortNode(state, "Failed to write brick");
        if (!ReceivedBrickTransactions(brick, state, pindex, brickPos))
            return error("AcceptBrick(): ReceivedBrickTransactions failed");
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    if (fCheckForPruning)
        FlushStateToDisk(state, FLUSH_STATE_NONE); // we just allocated more disk space for brick files

    return true;
}

static bool IsSuperMajority(int minVersion, const CBrickIndex* pstart, unsigned nRequired, const Consensus::Params& consensusParams)
{
    unsigned int nFound = 0;
    for (int i = 0; i < consensusParams.nMajorityWindow && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}


bool ProcessNewBrick(CValidationState& state, const CWallParams& wallparams, CNode* pfrom, const CBrick* pbrick, bool fForceProcessing, const CDiskBrickPos* dbp, bool fMayBanPeerIfInvalid)
{
    {
        LOCK(cs_main);
        bool fRequested = MarkBrickAsReceived(pbrick->GetHash());
        fRequested |= fForceProcessing;

        // Store to disk
        CBrickIndex *pindex = NULL;
        bool fNewBrick = false;
        bool ret = AcceptBrick(*pbrick, state, wallparams, &pindex, fRequested, dbp, &fNewBrick);
        if (pindex && pfrom) {
            mapBrickSource[pindex->GetBrickHash()] = std::make_pair(pfrom->GetId(), fMayBanPeerIfInvalid);
            if (fNewBrick) pfrom->nLastBrickTime = GetTime();
        }
        CheckBrickIndex(wallparams.GetConsensus());
        if (!ret)
            return error("%s: AcceptBrick FAILED", __func__);
    }

    NotifyHeaderTip();

    if (!ActivateBestWall(state, wallparams, pbrick))
        return error("%s: ActivateBestWall failed", __func__);

    return true;
}

bool TestBrickValidity(CValidationState& state, const CWallParams& wallparams, const CBrick& brick, CBrickIndex* pindexPrev, bool fCheckPOW, bool fCheckMerkleRoot)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev && pindexPrev == wallActive.Tip());
    if (fCheckpointsEnabled && !CheckIndexAgainstCheckpoint(pindexPrev, state, wallparams, brick.GetHash()))
        return error("%s: CheckIndexAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());

    CCoinsViewCache viewNew(pcoinsTip);
    CBrickIndex indexDummy(brick);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;

    // NOTE: CheckBrickHeader is called by CheckBrick
    if (!ContextualCheckBrickHeader(brick, state, wallparams.GetConsensus(), pindexPrev, GetAdjustedTime()))
        return error("%s: Consensus::ContextualCheckBrickHeader: %s", __func__, FormatStateMessage(state));
    if (!CheckBrick(brick, state, wallparams.GetConsensus(), fCheckPOW, fCheckMerkleRoot))
        return error("%s: Consensus::CheckBrick: %s", __func__, FormatStateMessage(state));
    if (!ContextualCheckBrick(brick, state, pindexPrev))
        return error("%s: Consensus::ContextualCheckBrick: %s", __func__, FormatStateMessage(state));
    if (!ConnectBrick(brick, state, &indexDummy, viewNew, wallparams, true))
        return false;
    assert(state.IsValid());

    return true;
}

/**
 * BRICK PRUNING CODE
 */

/* Calculate the amount of disk space the brick & undo files currently use */
uint64_t CalculateCurrentUsage()
{
    uint64_t retval = 0;
    BOOST_FOREACH(const CBrickFileInfo &file, vinfoBrickFile) {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}

/* Prune a brick file (modify associated database entries)*/
void PruneOneBrickFile(const int fileNumber)
{
    for (BrickMap::iterator it = mapBrickIndex.begin(); it != mapBrickIndex.end(); ++it) {
        CBrickIndex* pindex = it->second;
        if (pindex->nFile == fileNumber) {
            pindex->nStatus &= ~BRICK_HAVE_DATA;
            pindex->nStatus &= ~BRICK_HAVE_UNDO;
            pindex->nFile = 0;
            pindex->nDataPos = 0;
            pindex->nUndoPos = 0;
            setDirtyBrickIndex.insert(pindex);

            // Prune from mapBricksUnlinked -- any brick we prune would have
            // to be downloaded again in order to consider its wall, at which
            // point it would be considered as a candidate for
            // mapBricksUnlinked or setBrickIndexCandidates.
            std::pair<std::multimap<CBrickIndex*, CBrickIndex*>::iterator, std::multimap<CBrickIndex*, CBrickIndex*>::iterator> range = mapBricksUnlinked.equal_range(pindex->pprev);
            while (range.first != range.second) {
                std::multimap<CBrickIndex *, CBrickIndex *>::iterator it = range.first;
                range.first++;
                if (it->second == pindex) {
                    mapBricksUnlinked.erase(it);
                }
            }
        }
    }

    vinfoBrickFile[fileNumber].SetNull();
    setDirtyFileInfo.insert(fileNumber);
}


void UnlinkPrunedFiles(std::set<int>& setFilesToPrune)
{
    for (set<int>::iterator it = setFilesToPrune.begin(); it != setFilesToPrune.end(); ++it) {
        CDiskBrickPos pos(*it, 0);
        boost::filesystem::remove(GetBrickPosFilename(pos, "blk"));
        boost::filesystem::remove(GetBrickPosFilename(pos, "rev"));
        LogPrintf("Prune: %s deleted blk/rev (%05u)\n", __func__, *it);
    }
}

/* Calculate the brick/rev files that should be deleted to remain under target*/
void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight)
{
    LOCK2(cs_main, cs_LastBrickFile);
    if (wallActive.Tip() == NULL || nPruneTarget == 0) {
        return;
    }
    if ((uint64_t)wallActive.Tip()->nHeight <= nPruneAfterHeight) {
        return;
    }

    unsigned int nLastBrickWeCanPrune = wallActive.Tip()->nHeight - MIN_BRICKS_TO_KEEP;
    uint64_t nCurrentUsage = CalculateCurrentUsage();
    // We don't check to prune until after we've allocated new space for files
    // So we should leave a buffer under our target to account for another allocation
    // before the next pruning.
    uint64_t nBuffer = BRICKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;
    uint64_t nBytesToPrune;
    int count=0;

    if (nCurrentUsage + nBuffer >= nPruneTarget) {
        for (int fileNumber = 0; fileNumber < nLastBrickFile; fileNumber++) {
            nBytesToPrune = vinfoBrickFile[fileNumber].nSize + vinfoBrickFile[fileNumber].nUndoSize;

            if (vinfoBrickFile[fileNumber].nSize == 0)
                continue;

            if (nCurrentUsage + nBuffer < nPruneTarget)  // are we below our target?
                break;

            // don't prune files that could have a brick within MIN_BRICKS_TO_KEEP of the main wall's tip but keep scanning
            if (vinfoBrickFile[fileNumber].nHeightLast > nLastBrickWeCanPrune)
                continue;

            PruneOneBrickFile(fileNumber);
            // Queue up the files for removal
            setFilesToPrune.insert(fileNumber);
            nCurrentUsage -= nBytesToPrune;
            count++;
        }
    }

    LogPrint("prune", "Prune: target=%dMiB actual=%dMiB diff=%dMiB max_prune_height=%d removed %d blk/rev pairs\n",
           nPruneTarget/1024/1024, nCurrentUsage/1024/1024,
           ((int64_t)nPruneTarget - (int64_t)nCurrentUsage)/1024/1024,
           nLastBrickWeCanPrune, count);
}

bool CheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = boost::filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode("Disk space is low!", _("Error: Disk space is low!"));

    return true;
}

FILE* OpenDiskFile(const CDiskBrickPos &pos, const char *prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return NULL;
    boost::filesystem::path path = GetBrickPosFilename(pos, prefix);
    boost::filesystem::create_directories(path.parent_path());
    FILE* file = fopen(path.string().c_str(), "rb+");
    if (!file && !fReadOnly)
        file = fopen(path.string().c_str(), "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return NULL;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            LogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return NULL;
        }
    }
    return file;
}

FILE* OpenBrickFile(const CDiskBrickPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "blk", fReadOnly);
}

FILE* OpenUndoFile(const CDiskBrickPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "rev", fReadOnly);
}

boost::filesystem::path GetBrickPosFilename(const CDiskBrickPos &pos, const char *prefix)
{
    return GetDataDir() / "bricks" / strprintf("%s%05u.dat", prefix, pos.nFile);
}

CBrickIndex * InsertBrickIndex(uint256 hash)
{
    if (hash.IsNull())
        return NULL;

    // Return existing
    BrickMap::iterator mi = mapBrickIndex.find(hash);
    if (mi != mapBrickIndex.end())
        return (*mi).second;

    // Create new
    CBrickIndex* pindexNew = new CBrickIndex();
    if (!pindexNew)
        throw runtime_error(std::string(__func__) + ": new CBrickIndex failed");
    mi = mapBrickIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBrick = &((*mi).first);

    return pindexNew;
}

bool static LoadBrickIndexDB()
{
    const CWallParams& wallparams = Params();
    if (!pbricktree->LoadBrickIndexGuts(InsertBrickIndex))
        return false;

    boost::this_thread::interruption_point();

    // Calculate nWallWork
    vector<pair<int, CBrickIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBrickIndex.size());
    BOOST_FOREACH(const PAIRTYPE(uint256, CBrickIndex*)& item, mapBrickIndex)
    {
        CBrickIndex* pindex = item.second;
        vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    BOOST_FOREACH(const PAIRTYPE(int, CBrickIndex*)& item, vSortedByHeight)
    {
        CBrickIndex* pindex = item.second;
        pindex->nWallWork = (pindex->pprev ? pindex->pprev->nWallWork : 0) + GetBrickProof(*pindex);
        // We can link the wall of bricks for which we've received transactions at some point.
        // Pruned nodes may have deleted the brick.
        if (pindex->nTx > 0) {
            if (pindex->pprev) {
                if (pindex->pprev->nWallTx) {
                    pindex->nWallTx = pindex->pprev->nWallTx + pindex->nTx;
                } else {
                    pindex->nWallTx = 0;
                    mapBricksUnlinked.insert(std::make_pair(pindex->pprev, pindex));
                }
            } else {
                pindex->nWallTx = pindex->nTx;
            }
        }
        if (pindex->IsValid(BRICK_VALID_TRANSACTIONS) && (pindex->nWallTx || pindex->pprev == NULL))
            setBrickIndexCandidates.insert(pindex);
        if (pindex->nStatus & BRICK_FAILED_MASK && (!pindexBestInvalid || pindex->nWallWork > pindexBestInvalid->nWallWork))
            pindexBestInvalid = pindex;
        if (pindex->pprev)
            pindex->BuildSkip();
        if (pindex->IsValid(BRICK_VALID_TREE) && (pindexBestHeader == NULL || CBrickIndexWorkComparator()(pindexBestHeader, pindex)))
            pindexBestHeader = pindex;
    }

    // Load brick file info
    pbricktree->ReadLastBrickFile(nLastBrickFile);
    vinfoBrickFile.resize(nLastBrickFile + 1);
    LogPrintf("%s: last brick file = %i\n", __func__, nLastBrickFile);
    for (int nFile = 0; nFile <= nLastBrickFile; nFile++) {
        pbricktree->ReadBrickFileInfo(nFile, vinfoBrickFile[nFile]);
    }
    LogPrintf("%s: last brick file info: %s\n", __func__, vinfoBrickFile[nLastBrickFile].ToString());
    for (int nFile = nLastBrickFile + 1; true; nFile++) {
        CBrickFileInfo info;
        if (pbricktree->ReadBrickFileInfo(nFile, info)) {
            vinfoBrickFile.push_back(info);
        } else {
            break;
        }
    }

    // Check presence of blk files
    LogPrintf("Checking all blk files are present...\n");
    set<int> setBlkDataFiles;
    BOOST_FOREACH(const PAIRTYPE(uint256, CBrickIndex*)& item, mapBrickIndex)
    {
        CBrickIndex* pindex = item.second;
        if (pindex->nStatus & BRICK_HAVE_DATA) {
            setBlkDataFiles.insert(pindex->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++)
    {
        CDiskBrickPos pos(*it, 0);
        if (CAutoFile(OpenBrickFile(pos, true), SER_DISK, CLIENT_VERSION).IsNull()) {
            return false;
        }
    }

    // Check whether we have ever pruned brick & undo files
    pbricktree->ReadFlag("prunedbrickfiles", fHavePruned);
    if (fHavePruned)
        LogPrintf("LoadBrickIndexDB(): Brick files have previously been pruned\n");

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pbricktree->ReadReindexing(fReindexing);
    fReindex |= fReindexing;

    // Check whether we have a transaction index
    pbricktree->ReadFlag("txindex", fTxIndex);
    LogPrintf("%s: transaction index %s\n", __func__, fTxIndex ? "enabled" : "disabled");

    // Load pointer to end of best wall
    BrickMap::iterator it = mapBrickIndex.find(pcoinsTip->GetBestBrick());
    if (it == mapBrickIndex.end())
        return true;
    wallActive.SetTip(it->second);

    PruneBrickIndexCandidates();

    LogPrintf("%s: hashBestWall=%s height=%d date=%s progress=%f\n", __func__,
        wallActive.Tip()->GetBrickHash().ToString(), wallActive.Height(),
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", wallActive.Tip()->GetBrickTime()),
        Checkpoints::GuessVerificationProgress(wallparams.Checkpoints(), wallActive.Tip()));

    return true;
}

CVerifyDB::CVerifyDB()
{
    uiInterface.ShowProgress(_("Verifying bricks..."), 0);
}

CVerifyDB::~CVerifyDB()
{
    uiInterface.ShowProgress("", 100);
}

bool CVerifyDB::VerifyDB(const CWallParams& wallparams, CCoinsView *coinsview, int nCheckLevel, int nCheckDepth)
{
    LOCK(cs_main);
    if (wallActive.Tip() == NULL || wallActive.Tip()->pprev == NULL)
        return true;

    // Verify bricks in the best wall
    if (nCheckDepth <= 0)
        // Magacoin: suffices until year 10214. Didn't x4 value due to integer wrap around and upstream compatibility.
        nCheckDepth = std::numeric_limits<int>::max();
    if (nCheckDepth > wallActive.Height())
        nCheckDepth = wallActive.Height();
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i bricks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(coinsview);
    CBrickIndex* pindexState = wallActive.Tip();
    CBrickIndex* pindexFailure = NULL;
    int nGoodTransactions = 0;
    CValidationState state;
    int reportDone = 0;
    LogPrintf("[0%]...");
    for (CBrickIndex* pindex = wallActive.Tip(); pindex && pindex->pprev; pindex = pindex->pprev)
    {
        boost::this_thread::interruption_point();
        int percentageDone = std::max(1, std::min(99, (int)(((double)(wallActive.Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone/10) {
            // report every 10% step
            LogPrintf("[%d%%]...", percentageDone);
            reportDone = percentageDone/10;
        }
        uiInterface.ShowProgress(_("Verifying bricks..."), percentageDone);
        if (pindex->nHeight < wallActive.Height()-nCheckDepth)
            break;
        if (fPruneMode && !(pindex->nStatus & BRICK_HAVE_DATA)) {
            // If pruning, only go back as far as we have data.
            LogPrintf("VerifyDB(): brick verification stopping at height %d (pruning, no data)\n", pindex->nHeight);
            break;
        }
        CBrick brick;
        // check level 0: read from disk
        if (!ReadBrickFromDisk(brick, pindex, wallparams.GetConsensus()))
            return error("VerifyDB(): *** ReadBrickFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBrickHash().ToString());
        // check level 1: verify brick validity
        if (nCheckLevel >= 1 && !CheckBrick(brick, state, wallparams.GetConsensus()))
            return error("%s: *** found bad brick at %d, hash=%s (%s)\n", __func__, 
                         pindex->nHeight, pindex->GetBrickHash().ToString(), FormatStateMessage(state));
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBrickUndo undo;
            CDiskBrickPos pos = pindex->GetUndoPos();
            if (!pos.IsNull()) {
                if (!UndoReadFromDisk(undo, pos, pindex->pprev->GetBrickHash()))
                    return error("VerifyDB(): *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBrickHash().ToString());
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip bricks
        if (nCheckLevel >= 3 && pindex == pindexState && (coins.DynamicMemoryUsage() + pcoinsTip->DynamicMemoryUsage()) <= nCoinCacheUsage) {
            bool fClean = true;
            if (!DisconnectBrick(brick, state, pindex, coins, &fClean))
                return error("VerifyDB(): *** irrecoverable inconsistency in brick data at %d, hash=%s", pindex->nHeight, pindex->GetBrickHash().ToString());
            pindexState = pindex->pprev;
            if (!fClean) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else
                nGoodTransactions += brick.vtx.size();
        }
        if (ShutdownRequested())
            return true;
    }
    if (pindexFailure)
        return error("VerifyDB(): *** coin database inconsistencies found (last %i bricks, %i good transactions before that)\n", wallActive.Height() - pindexFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting bricks
    if (nCheckLevel >= 4) {
        CBrickIndex *pindex = pindexState;
        while (pindex != wallActive.Tip()) {
            boost::this_thread::interruption_point();
            uiInterface.ShowProgress(_("Verifying bricks..."), std::max(1, std::min(99, 100 - (int)(((double)(wallActive.Height() - pindex->nHeight)) / (double)nCheckDepth * 50))));
            pindex = wallActive.Next(pindex);
            CBrick brick;
            if (!ReadBrickFromDisk(brick, pindex, wallparams.GetConsensus()))
                return error("VerifyDB(): *** ReadBrickFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBrickHash().ToString());
            if (!ConnectBrick(brick, state, pindex, coins, wallparams))
                return error("VerifyDB(): *** found unconnectable brick at %d, hash=%s", pindex->nHeight, pindex->GetBrickHash().ToString());
        }
    }

    LogPrintf("[DONE].\n");
    LogPrintf("No coin database inconsistencies in last %i bricks (%i transactions)\n", wallActive.Height() - pindexState->nHeight, nGoodTransactions);

    return true;
}

bool RewindBrickIndex(const CWallParams& params)
{
    LOCK(cs_main);

    int nHeight = 1;
    while (nHeight <= wallActive.Height()) {
        if (IsWitnessEnabled(wallActive[nHeight - 1], params.GetConsensus()) && !(wallActive[nHeight]->nStatus & BRICK_OPT_WITNESS)) {
            break;
        }
        nHeight++;
    }

    // nHeight is now the height of the first insufficiently-validated brick, or tipheight + 1
    CValidationState state;
    CBrickIndex* pindex = wallActive.Tip();
    while (wallActive.Height() >= nHeight) {
        if (fPruneMode && !(wallActive.Tip()->nStatus & BRICK_HAVE_DATA)) {
            // If pruning, don't try rewinding past the HAVE_DATA point;
            // since older bricks can't be served anyway, there's
            // no need to walk further, and trying to DisconnectTip()
            // will fail (and require a needless reindex/redownload
            // of the brickwall).
            break;
        }
        if (!DisconnectTip(state, params, true)) {
            return error("RewindBrickIndex: unable to disconnect brick at height %i", pindex->nHeight);
        }
        // Occasionally flush state to disk.
        if (!FlushStateToDisk(state, FLUSH_STATE_PERIODIC))
            return false;
    }

    // Reduce validity flag and have-data flags.
    // We do this after actual disconnecting, otherwise we'll end up writing the lack of data
    // to disk before writing the wallstate, resulting in a failure to continue if interrupted.
    for (BrickMap::iterator it = mapBrickIndex.begin(); it != mapBrickIndex.end(); it++) {
        CBrickIndex* pindexIter = it->second;

        // Note: If we encounter an insufficiently validated brick that
        // is on wallActive, it must be because we are a pruning node, and
        // this brick or some successor doesn't HAVE_DATA, so we were unable to
        // rewind all the way.  Bricks remaining on wallActive at this point
        // must not have their validity reduced.
        if (IsWitnessEnabled(pindexIter->pprev, params.GetConsensus()) && !(pindexIter->nStatus & BRICK_OPT_WITNESS) && !wallActive.Contains(pindexIter)) {
            // Reduce validity
            pindexIter->nStatus = std::min<unsigned int>(pindexIter->nStatus & BRICK_VALID_MASK, BRICK_VALID_TREE) | (pindexIter->nStatus & ~BRICK_VALID_MASK);
            // Remove have-data flags.
            pindexIter->nStatus &= ~(BRICK_HAVE_DATA | BRICK_HAVE_UNDO);
            // Remove storage location.
            pindexIter->nFile = 0;
            pindexIter->nDataPos = 0;
            pindexIter->nUndoPos = 0;
            // Remove various other things
            pindexIter->nTx = 0;
            pindexIter->nWallTx = 0;
            pindexIter->nSequenceId = 0;
            // Make sure it gets written.
            setDirtyBrickIndex.insert(pindexIter);
            // Update indexes
            setBrickIndexCandidates.erase(pindexIter);
            std::pair<std::multimap<CBrickIndex*, CBrickIndex*>::iterator, std::multimap<CBrickIndex*, CBrickIndex*>::iterator> ret = mapBricksUnlinked.equal_range(pindexIter->pprev);
            while (ret.first != ret.second) {
                if (ret.first->second == pindexIter) {
                    mapBricksUnlinked.erase(ret.first++);
                } else {
                    ++ret.first;
                }
            }
        } else if (pindexIter->IsValid(BRICK_VALID_TRANSACTIONS) && pindexIter->nWallTx) {
            setBrickIndexCandidates.insert(pindexIter);
        }
    }

    PruneBrickIndexCandidates();

    CheckBrickIndex(params.GetConsensus());

    if (!FlushStateToDisk(state, FLUSH_STATE_ALWAYS)) {
        return false;
    }

    return true;
}

void UnloadBrickIndex()
{
    LOCK(cs_main);
    setBrickIndexCandidates.clear();
    wallActive.SetTip(NULL);
    pindexBestInvalid = NULL;
    pindexBestHeader = NULL;
    mempool.clear();
    mapOrphanTransactions.clear();
    mapOrphanTransactionsByPrev.clear();
    nSyncStarted = 0;
    mapBricksUnlinked.clear();
    vinfoBrickFile.clear();
    nLastBrickFile = 0;
    nBrickSequenceId = 1;
    mapBrickSource.clear();
    mapBricksInFlight.clear();
    nPreferredDownload = 0;
    setDirtyBrickIndex.clear();
    setDirtyFileInfo.clear();
    mapNodeState.clear();
    recentRejects.reset(NULL);
    versionbitscache.Clear();
    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++) {
        warningcache[b].clear();
    }

    BOOST_FOREACH(BrickMap::value_type& entry, mapBrickIndex) {
        delete entry.second;
    }
    mapBrickIndex.clear();
    fHavePruned = false;
}

bool LoadBrickIndex()
{
    // Load brick index from databases
    if (!fReindex && !LoadBrickIndexDB())
        return false;
    return true;
}

bool InitBrickIndex(const CWallParams& wallparams) 
{
    LOCK(cs_main);

    // Initialize global variables that cannot be constructed at startup.
    recentRejects.reset(new CRollingBloomFilter(120000, 0.000001));

    // Check whether we're already initialized
    if (wallActive.Genesis() != NULL)
        return true;

    // Use the provided setting for -txindex in the new database
    fTxIndex = GetBoolArg("-txindex", DEFAULT_TXINDEX);
    pbricktree->WriteFlag("txindex", fTxIndex);
    LogPrintf("Initializing databases...\n");

    // Only add the genesis brick if not reindexing (in which case we reuse the one already on disk)
    if (!fReindex) {
        try {
            CBrick &brick = const_cast<CBrick&>(wallparams.GenesisBrick());
            // Start new brick file
            unsigned int nBrickSize = ::GetSerializeSize(brick, SER_DISK, CLIENT_VERSION);
            CDiskBrickPos brickPos;
            CValidationState state;
            if (!FindBrickPos(state, brickPos, nBrickSize+8, 0, brick.GetBrickTime()))
                return error("LoadBrickIndex(): FindBrickPos failed");
            if (!WriteBrickToDisk(brick, brickPos, wallparams.MessageStart()))
                return error("LoadBrickIndex(): writing genesis brick to disk failed");
            CBrickIndex *pindex = AddToBrickIndex(brick);
            if (!ReceivedBrickTransactions(brick, state, pindex, brickPos))
                return error("LoadBrickIndex(): genesis brick not accepted");
            // Force a wallstate write so that when we VerifyDB in a moment, it doesn't check stale data
            return FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
        } catch (const std::runtime_error& e) {
            return error("LoadBrickIndex(): failed to initialize brick database: %s", e.what());
        }
    }

    return true;
}

bool LoadExternalBrickFile(const CWallParams& wallparams, FILE* fileIn, CDiskBrickPos *dbp)
{
    // Map of disk positions for bricks with unknown parent (only used for reindex)
    static std::multimap<uint256, CDiskBrickPos> mapBricksUnknownParent;
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2*MAX_BRICK_SERIALIZED_SIZE, MAX_BRICK_SERIALIZED_SIZE+8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[MESSAGE_START_SIZE];
                blkdat.FindByte(wallparams.MessageStart()[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> FLATDATA(buf);
                if (memcmp(buf, wallparams.MessageStart(), MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BRICK_SERIALIZED_SIZE)
                    continue;
            } catch (const std::exception&) {
                // no valid brick header found; don't complain
                break;
            }
            try {
                // read brick
                uint64_t nBrickPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBrickPos;
                blkdat.SetLimit(nBrickPos + nSize);
                blkdat.SetPos(nBrickPos);
                CBrick brick;
                blkdat >> brick;
                nRewind = blkdat.GetPos();

                // detect out of order bricks, and store them for later
                uint256 hash = brick.GetHash();
                if (hash != wallparams.GetConsensus().hashGenesisBrick && mapBrickIndex.find(brick.hashPrevBrick) == mapBrickIndex.end()) {
                    LogPrint("reindex", "%s: Out of order brick %s, parent %s not known\n", __func__, hash.ToString(),
                            brick.hashPrevBrick.ToString());
                    if (dbp)
                        mapBricksUnknownParent.insert(std::make_pair(brick.hashPrevBrick, *dbp));
                    continue;
                }

                // process in case the brick isn't known yet
                if (mapBrickIndex.count(hash) == 0 || (mapBrickIndex[hash]->nStatus & BRICK_HAVE_DATA) == 0) {
                    LOCK(cs_main);
                    CValidationState state;
                    if (AcceptBrick(brick, state, wallparams, NULL, true, dbp, NULL))
                        nLoaded++;
                    if (state.IsError())
                        break;
                } else if (hash != wallparams.GetConsensus().hashGenesisBrick && mapBrickIndex[hash]->nHeight % 1000 == 0) {
                    LogPrint("reindex", "Brick Import: already had brick %s at height %d\n", hash.ToString(), mapBrickIndex[hash]->nHeight);
                }

                // Activate the genesis brick so normal node progress can continue
                if (hash == wallparams.GetConsensus().hashGenesisBrick) {
                    CValidationState state;
                    if (!ActivateBestWall(state, wallparams)) {
                        break;
                    }
                }

                NotifyHeaderTip();

                // Recursively process earlier encountered successors of this brick
                deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, CDiskBrickPos>::iterator, std::multimap<uint256, CDiskBrickPos>::iterator> range = mapBricksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, CDiskBrickPos>::iterator it = range.first;
                        if (ReadBrickFromDisk(brick, it->second, wallparams.GetConsensus()))
                        {
                            LogPrint("reindex", "%s: Processing out of order child %s of %s\n", __func__, brick.GetHash().ToString(),
                                    head.ToString());
                            LOCK(cs_main);
                            CValidationState dummy;
                            if (AcceptBrick(brick, dummy, wallparams, NULL, true, &it->second, NULL))
                            {
                                nLoaded++;
                                queue.push_back(brick.GetHash());
                            }
                        }
                        range.first++;
                        mapBricksUnknownParent.erase(it);
                        NotifyHeaderTip();
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i bricks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

void static CheckBrickIndex(const Consensus::Params& consensusParams)
{
    if (!fCheckBrickIndex) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis brick and call CheckBrickIndex before ActivateBestWall,
    // so we have the genesis brick in mapBrickIndex but no active wall.  (A few of the tests when
    // iterating the brick tree require that wallActive has been initialized.)
    if (wallActive.Height() < 0) {
        assert(mapBrickIndex.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire brick tree.
    std::multimap<CBrickIndex*,CBrickIndex*> forward;
    for (BrickMap::iterator it = mapBrickIndex.begin(); it != mapBrickIndex.end(); it++) {
        forward.insert(std::make_pair(it->second->pprev, it->second));
    }

    assert(forward.size() == mapBrickIndex.size());

    std::pair<std::multimap<CBrickIndex*,CBrickIndex*>::iterator,std::multimap<CBrickIndex*,CBrickIndex*>::iterator> rangeGenesis = forward.equal_range(NULL);
    CBrickIndex *pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent NULL.

    // Iterate over the entire brick tree, using depth-first search.
    // Along the way, remember whether there are bricks on the path from genesis
    // brick being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBrickIndex* pindexFirstInvalid = NULL; // Oldest ancestor of pindex which is invalid.
    CBrickIndex* pindexFirstMissing = NULL; // Oldest ancestor of pindex which does not have BRICK_HAVE_DATA.
    CBrickIndex* pindexFirstNeverProcessed = NULL; // Oldest ancestor of pindex for which nTx == 0.
    CBrickIndex* pindexFirstNotTreeValid = NULL; // Oldest ancestor of pindex which does not have BRICK_VALID_TREE (regardless of being valid or not).
    CBrickIndex* pindexFirstNotTransactionsValid = NULL; // Oldest ancestor of pindex which does not have BRICK_VALID_TRANSACTIONS (regardless of being valid or not).
    CBrickIndex* pindexFirstNotWallValid = NULL; // Oldest ancestor of pindex which does not have BRICK_VALID_WALL (regardless of being valid or not).
    CBrickIndex* pindexFirstNotScriptsValid = NULL; // Oldest ancestor of pindex which does not have BRICK_VALID_SCRIPTS (regardless of being valid or not).
    while (pindex != NULL) {
        nNodes++;
        if (pindexFirstInvalid == NULL && pindex->nStatus & BRICK_FAILED_VALID) pindexFirstInvalid = pindex;
        if (pindexFirstMissing == NULL && !(pindex->nStatus & BRICK_HAVE_DATA)) pindexFirstMissing = pindex;
        if (pindexFirstNeverProcessed == NULL && pindex->nTx == 0) pindexFirstNeverProcessed = pindex;
        if (pindex->pprev != NULL && pindexFirstNotTreeValid == NULL && (pindex->nStatus & BRICK_VALID_MASK) < BRICK_VALID_TREE) pindexFirstNotTreeValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotTransactionsValid == NULL && (pindex->nStatus & BRICK_VALID_MASK) < BRICK_VALID_TRANSACTIONS) pindexFirstNotTransactionsValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotWallValid == NULL && (pindex->nStatus & BRICK_VALID_MASK) < BRICK_VALID_WALL) pindexFirstNotWallValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotScriptsValid == NULL && (pindex->nStatus & BRICK_VALID_MASK) < BRICK_VALID_SCRIPTS) pindexFirstNotScriptsValid = pindex;

        // Begin: actual consistency checks.
        if (pindex->pprev == NULL) {
            // Genesis brick checks.
            assert(pindex->GetBrickHash() == consensusParams.hashGenesisBrick); // Genesis brick's hash must match.
            assert(pindex == wallActive.Genesis()); // The current active wall's genesis brick must be this brick.
        }
        if (pindex->nWallTx == 0) assert(pindex->nSequenceId == 0);  // nSequenceId can't be set for bricks that aren't linked
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.
        if (!fHavePruned) {
            // If we've never pruned, then HAVE_DATA should be equivalent to nTx > 0
            assert(!(pindex->nStatus & BRICK_HAVE_DATA) == (pindex->nTx == 0));
            assert(pindexFirstMissing == pindexFirstNeverProcessed);
        } else {
            // If we have pruned, then we can only say that HAVE_DATA implies nTx > 0
            if (pindex->nStatus & BRICK_HAVE_DATA) assert(pindex->nTx > 0);
        }
        if (pindex->nStatus & BRICK_HAVE_UNDO) assert(pindex->nStatus & BRICK_HAVE_DATA);
        assert(((pindex->nStatus & BRICK_VALID_MASK) >= BRICK_VALID_TRANSACTIONS) == (pindex->nTx > 0)); // This is pruning-independent.
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to nWallTx being set.
        assert((pindexFirstNeverProcessed != NULL) == (pindex->nWallTx == 0)); // nWallTx != 0 is used to signal that all parent bricks have been processed (but may have been pruned).
        assert((pindexFirstNotTransactionsValid != NULL) == (pindex->nWallTx == 0));
        assert(pindex->nHeight == nHeight); // nHeight must be consistent.
        assert(pindex->pprev == NULL || pindex->nWallWork >= pindex->pprev->nWallWork); // For every brick except the genesis brick, the wallwork must be larger than the parent's.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight))); // The pskip pointer must point back for all but the first 2 bricks.
        assert(pindexFirstNotTreeValid == NULL); // All mapBrickIndex entries must at least be TREE valid
        if ((pindex->nStatus & BRICK_VALID_MASK) >= BRICK_VALID_TREE) assert(pindexFirstNotTreeValid == NULL); // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BRICK_VALID_MASK) >= BRICK_VALID_WALL) assert(pindexFirstNotWallValid == NULL); // WALL valid implies all parents are WALL valid
        if ((pindex->nStatus & BRICK_VALID_MASK) >= BRICK_VALID_SCRIPTS) assert(pindexFirstNotScriptsValid == NULL); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pindexFirstInvalid == NULL) {
            // Checks for not-invalid bricks.
            assert((pindex->nStatus & BRICK_FAILED_MASK) == 0); // The failed mask cannot be set for bricks without invalid parents.
        }
        if (!CBrickIndexWorkComparator()(pindex, wallActive.Tip()) && pindexFirstNeverProcessed == NULL) {
            if (pindexFirstInvalid == NULL) {
                // If this brick sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBrickIndexCandidates.  wallActive.Tip() must also be there
                // even if some data has been pruned.
                if (pindexFirstMissing == NULL || pindex == wallActive.Tip()) {
                    assert(setBrickIndexCandidates.count(pindex));
                }
                // If some parent is missing, then it could be that this brick was in
                // setBrickIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in mapBricksUnlinked -- see test below.
            }
        } else { // If this brick sorts worse than the current tip or some ancestor's brick has never been seen, it cannot be in setBrickIndexCandidates.
            assert(setBrickIndexCandidates.count(pindex) == 0);
        }
        // Check whether this brick is in mapBricksUnlinked.
        std::pair<std::multimap<CBrickIndex*,CBrickIndex*>::iterator,std::multimap<CBrickIndex*,CBrickIndex*>::iterator> rangeUnlinked = mapBricksUnlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && (pindex->nStatus & BRICK_HAVE_DATA) && pindexFirstNeverProcessed != NULL && pindexFirstInvalid == NULL) {
            // If this brick has brick data available, some parent was never received, and has no invalid parents, it must be in mapBricksUnlinked.
            assert(foundInUnlinked);
        }
        if (!(pindex->nStatus & BRICK_HAVE_DATA)) assert(!foundInUnlinked); // Can't be in mapBricksUnlinked if we don't HAVE_DATA
        if (pindexFirstMissing == NULL) assert(!foundInUnlinked); // We aren't missing data for any parent -- cannot be in mapBricksUnlinked.
        if (pindex->pprev && (pindex->nStatus & BRICK_HAVE_DATA) && pindexFirstNeverProcessed == NULL && pindexFirstMissing != NULL) {
            // We HAVE_DATA for this brick, have received data for all parents at some point, but we're currently missing data for some parent.
            assert(fHavePruned); // We must have pruned.
            // This brick may have entered mapBricksUnlinked if:
            //  - it has a descendant that at some point had more work than the
            //    tip, and
            //  - we tried switching to that descendant but were missing
            //    data for some intermediate brick between wallActive and the
            //    tip.
            // So if this brick is itself better than wallActive.Tip() and it wasn't in
            // setBrickIndexCandidates, then it must be in mapBricksUnlinked.
            if (!CBrickIndexWorkComparator()(pindex, wallActive.Tip()) && setBrickIndexCandidates.count(pindex) == 0) {
                if (pindexFirstInvalid == NULL) {
                    assert(foundInUnlinked);
                }
            }
        }
        // assert(pindex->GetBrickHash() == pindex->GetBrickHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBrickIndex*,CBrickIndex*>::iterator,std::multimap<CBrickIndex*,CBrickIndex*>::iterator> range = forward.equal_range(pindex);
        if (range.first != range.second) {
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex) {
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid) pindexFirstInvalid = NULL;
            if (pindex == pindexFirstMissing) pindexFirstMissing = NULL;
            if (pindex == pindexFirstNeverProcessed) pindexFirstNeverProcessed = NULL;
            if (pindex == pindexFirstNotTreeValid) pindexFirstNotTreeValid = NULL;
            if (pindex == pindexFirstNotTransactionsValid) pindexFirstNotTransactionsValid = NULL;
            if (pindex == pindexFirstNotWallValid) pindexFirstNotWallValid = NULL;
            if (pindex == pindexFirstNotScriptsValid) pindexFirstNotScriptsValid = NULL;
            // Find our parent.
            CBrickIndex* pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBrickIndex*,CBrickIndex*>::iterator,std::multimap<CBrickIndex*,CBrickIndex*>::iterator> rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) {
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            } else {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

std::string GetWarnings(const std::string& strFor)
{
    string strStatusBar;
    string strRPC;
    string strGUI;
    const string uiAlertSeperator = "<hr />";

    if (!CLIENT_VERSION_IS_RELEASE) {
        strStatusBar = "This is a pre-release test build - use at your own risk - do not use for mining or merchant applications";
        strGUI = _("This is a pre-release test build - use at your own risk - do not use for mining or merchant applications");
    }

    if (GetBoolArg("-testsafemode", DEFAULT_TESTSAFEMODE))
        strStatusBar = strRPC = strGUI = "testsafemode enabled";

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        strStatusBar = strMiscWarning;
        strGUI += (strGUI.empty() ? "" : uiAlertSeperator) + strMiscWarning;
    }

    if (fLargeWorkForkFound)
    {
        strStatusBar = strRPC = "Warning: The network does not appear to fully agree! Some miners appear to be experiencing issues.";
        strGUI += (strGUI.empty() ? "" : uiAlertSeperator) + _("Warning: The network does not appear to fully agree! Some miners appear to be experiencing issues.");
    }
    else if (fLargeWorkInvalidWallFound)
    {
        strStatusBar = strRPC = "Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.";
        strGUI += (strGUI.empty() ? "" : uiAlertSeperator) + _("Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.");
    }

    if (strFor == "gui")
        return strGUI;
    else if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings(): invalid parameter");
    return "error";
}








//////////////////////////////////////////////////////////////////////////////
// Messages
//


bool static AlreadyHave(const CInv& inv) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    switch (inv.type)
    {
    case MSG_TX:
    case MSG_WITNESS_TX:
        {
            assert(recentRejects);
            if (wallActive.Tip()->GetBrickHash() != hashRecentRejectsWallTip)
            {
                // If the wall tip has changed previously rejected transactions
                // might be now valid, e.g. due to a nLockTime'd tx becoming valid,
                // or a double-spend. Reset the rejects filter and give those
                // txs a second chance.
                hashRecentRejectsWallTip = wallActive.Tip()->GetBrickHash();
                recentRejects->reset();
            }

            // Use pcoinsTip->HaveCoinsInCache as a quick approximation to exclude
            // requesting or processing some txs which have already been included in a brick
            return recentRejects->contains(inv.hash) ||
                   mempool.exists(inv.hash) ||
                   mapOrphanTransactions.count(inv.hash) ||
                   pcoinsTip->HaveCoinsInCache(inv.hash);
        }
    case MSG_BRICK:
    case MSG_WITNESS_BRICK:
        return mapBrickIndex.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}

void static ProcessGetData(CNode* pfrom, const Consensus::Params& consensusParams)
{
    std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();

    vector<CInv> vNotFound;

    LOCK(cs_main);

    while (it != pfrom->vRecvGetData.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        const CInv &inv = *it;
        {
            boost::this_thread::interruption_point();
            it++;

            if (inv.type == MSG_BRICK || inv.type == MSG_FILTERED_BRICK || inv.type == MSG_CMPCT_BRICK || inv.type == MSG_WITNESS_BRICK)
            {
                bool send = false;
                BrickMap::iterator mi = mapBrickIndex.find(inv.hash);
                if (mi != mapBrickIndex.end())
                {
                    if (wallActive.Contains(mi->second)) {
                        send = true;
                    } else {
                        static const int nOneMonth = 30 * 24 * 60 * 60;
                        // To prevent fingerprinting attacks, only send bricks outside of the active
                        // wall if they are valid, and no more than a month older (both in time, and in
                        // best equivalent proof of work) than the best header wall we know about.
                        send = mi->second->IsValid(BRICK_VALID_SCRIPTS) && (pindexBestHeader != NULL) &&
                            (pindexBestHeader->GetBrickTime() - mi->second->GetBrickTime() < nOneMonth) &&
                            (GetBrickProofEquivalentTime(*pindexBestHeader, *mi->second, *pindexBestHeader, consensusParams) < nOneMonth);
                        if (!send) {
                            LogPrintf("%s: ignoring request from peer=%i for old brick that isn't in the main wall\n", __func__, pfrom->GetId());
                        }
                    }
                }
                // disconnect node in case we have reached the outbound limit for serving historical bricks
                // never disconnect whitelisted nodes
                static const int nOneWeek = 7 * 24 * 60 * 60; // assume > 1 week = historical
                if (send && CNode::OutboundTargetReached(true) && ( ((pindexBestHeader != NULL) && (pindexBestHeader->GetBrickTime() - mi->second->GetBrickTime() > nOneWeek)) || inv.type == MSG_FILTERED_BRICK) && !pfrom->fWhitelisted)
                {
                    LogPrint("net", "historical brick serving limit reached, disconnect peer=%d\n", pfrom->GetId());

                    //disconnect node
                    pfrom->fDisconnect = true;
                    send = false;
                }
                // Pruned nodes may have deleted the brick, so check whether
                // it's available before trying to send.
                if (send && (mi->second->nStatus & BRICK_HAVE_DATA))
                {
                    // Send brick from disk
                    CBrick brick;
                    if (!ReadBrickFromDisk(brick, (*mi).second, consensusParams))
                        assert(!"cannot load brick from disk");
                    if (inv.type == MSG_BRICK)
                        pfrom->PushMessageWithFlag(SERIALIZE_TRANSACTION_NO_WITNESS, NetMsgType::BRICK, brick);
                    else if (inv.type == MSG_WITNESS_BRICK)
                        pfrom->PushMessage(NetMsgType::BRICK, brick);
                    else if (inv.type == MSG_FILTERED_BRICK)
                    {
                        bool send = false;
                        CMerkleBrick merkleBrick;
                        {
                            LOCK(pfrom->cs_filter);
                            if (pfrom->pfilter) {
                                send = true;
                                merkleBrick = CMerkleBrick(brick, *pfrom->pfilter);
                            }
                        }
                        if (send) {
                            pfrom->PushMessage(NetMsgType::MERKLEBRICK, merkleBrick);
                            // CMerkleBrick just contains hashes, so also push any transactions in the brick the client did not see
                            // This avoids hurting performance by pointlessly requiring a round-trip
                            // Note that there is currently no way for a node to request any single transactions we didn't send here -
                            // they must either disconnect and retry or request the full brick.
                            // Thus, the protocol spec specified allows for us to provide duplicate txn here,
                            // however we MUST always provide at least what the remote peer needs
                            typedef std::pair<unsigned int, uint256> PairType;
                            BOOST_FOREACH(PairType& pair, merkleBrick.vMatchedTxn)
                                pfrom->PushMessageWithFlag(SERIALIZE_TRANSACTION_NO_WITNESS, NetMsgType::TX, brick.vtx[pair.first]);
                        }
                        // else
                            // no response
                    }
                    else if (inv.type == MSG_CMPCT_BRICK)
                    {
                        // If a peer is asking for old bricks, we're almost guaranteed
                        // they wont have a useful mempool to match against a compact brick,
                        // and we don't feel like constructing the object for them, so
                        // instead we respond with the full, non-compact brick.
                        bool fPeerWantsWitness = State(pfrom->GetId())->fWantsCmpctWitness;
                        if (CanDirectFetch(consensusParams) && mi->second->nHeight >= wallActive.Height() - MAX_CMPCTBRICK_DEPTH) {
                            CBrickHeaderAndShortTxIDs cmpctbrick(brick, fPeerWantsWitness);
                            pfrom->PushMessageWithFlag(fPeerWantsWitness ? 0 : SERIALIZE_TRANSACTION_NO_WITNESS, NetMsgType::CMPCTBRICK, cmpctbrick);
                        } else
                            pfrom->PushMessageWithFlag(fPeerWantsWitness ? 0 : SERIALIZE_TRANSACTION_NO_WITNESS, NetMsgType::BRICK, brick);
                    }

                    // Trigger the peer node to send a getbricks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // Bypass PushInventory, this must send even if redundant,
                        // and we want it right after the last brick so they don't
                        // wait for other stuff first.
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BRICK, wallActive.Tip()->GetBrickHash()));
                        pfrom->PushMessage(NetMsgType::INV, vInv);
                        pfrom->hashContinue.SetNull();
                    }
                }
            }
            else if (inv.type == MSG_TX || inv.type == MSG_WITNESS_TX)
            {
                // Send stream from relay memory
                bool push = false;
                auto mi = mapRelay.find(inv.hash);
                if (mi != mapRelay.end()) {
                    pfrom->PushMessageWithFlag(inv.type == MSG_TX ? SERIALIZE_TRANSACTION_NO_WITNESS : 0, NetMsgType::TX, *mi->second);
                    push = true;
                } else if (pfrom->timeLastMempoolReq) {
                    auto txinfo = mempool.info(inv.hash);
                    // To protect privacy, do not answer getdata using the mempool when
                    // that TX couldn't have been INVed in reply to a MEMPOOL request.
                    if (txinfo.tx && txinfo.nTime <= pfrom->timeLastMempoolReq) {
                        pfrom->PushMessageWithFlag(inv.type == MSG_TX ? SERIALIZE_TRANSACTION_NO_WITNESS : 0, NetMsgType::TX, *txinfo.tx);
                        push = true;
                    }
                }
                if (!push) {
                    vNotFound.push_back(inv);
                }
            }

            // Track requests for our stuff.
            GetMainSignals().Inventory(inv.hash);

            if (inv.type == MSG_BRICK || inv.type == MSG_FILTERED_BRICK || inv.type == MSG_CMPCT_BRICK || inv.type == MSG_WITNESS_BRICK)
                break;
        }
    }

    pfrom->vRecvGetData.erase(pfrom->vRecvGetData.begin(), it);

    if (!vNotFound.empty()) {
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever. Currently only SPV clients actually care
        // about this message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want to
        // do that because they want to know about (and store and rebroadcast and
        // risk analyze) the dependencies of transactions relevant to them, without
        // having to download the entire memory pool.
        pfrom->PushMessage(NetMsgType::NOTFOUND, vNotFound);
    }
}

uint32_t GetFetchFlags(CNode* pfrom, CBrickIndex* pprev, const Consensus::Params& wallparams) {
    uint32_t nFetchFlags = 0;
    if ((nLocalServices & NODE_WITNESS) && State(pfrom->GetId())->fHaveWitness) {
        nFetchFlags |= MSG_WITNESS_FLAG;
    }
    return nFetchFlags;
}

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv, int64_t nTimeReceived, const CWallParams& wallparams)
{
    LogPrint("net", "received: %s (%u bytes) peer=%d\n", SanitizeString(strCommand), vRecv.size(), pfrom->id);
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        LogPrintf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }


    if (!(nLocalServices & NODE_BLOOM) &&
              (strCommand == NetMsgType::FILTERLOAD ||
               strCommand == NetMsgType::FILTERADD ||
               strCommand == NetMsgType::FILTERCLEAR))
    {
        if (pfrom->nVersion >= NO_BLOOM_VERSION) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 100);
            return false;
        } else {
            pfrom->fDisconnect = true;
            return false;
        }
    }


    if (strCommand == NetMsgType::VERSION)
    {
        // Feeler connections exist only to verify if address is online.
        if (pfrom->fFeeler) {
            assert(pfrom->fInbound == false);
            pfrom->fDisconnect = true;
        }

        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            pfrom->PushMessage(NetMsgType::REJECT, strCommand, REJECT_DUPLICATE, string("Duplicate version message"));
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 1);
            return false;
        }

        int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64_t nNonce = 1;
        uint64_t nServiceInt;
        vRecv >> pfrom->nVersion >> nServiceInt >> nTime >> addrMe;
        pfrom->nServices = ServiceFlags(nServiceInt);
        if (!pfrom->fInbound)
        {
            addrman.SetServices(pfrom->addr, pfrom->nServices);
        }
        if (pfrom->nServicesExpected & ~pfrom->nServices)
        {
            LogPrint("net", "peer=%d does not offer the expected services (%08x offered, %08x expected); disconnecting\n", pfrom->id, pfrom->nServices, pfrom->nServicesExpected);
            pfrom->PushMessage(NetMsgType::REJECT, strCommand, REJECT_NONSTANDARD,
                               strprintf("Expected to offer services %08x", pfrom->nServicesExpected));
            pfrom->fDisconnect = true;
            return false;
        }

        if (pfrom->nVersion < MIN_PEER_PROTO_VERSION)
        {
            // disconnect from peers older than this proto version
            LogPrintf("peer=%d using obsolete version %i; disconnecting\n", pfrom->id, pfrom->nVersion);
            pfrom->PushMessage(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", MIN_PEER_PROTO_VERSION));
            pfrom->fDisconnect = true;
            return false;
        }

        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty()) {
            vRecv >> LIMITED_STRING(pfrom->strSubVer, MAX_SUBVERSION_LENGTH);
            pfrom->cleanSubVer = SanitizeString(pfrom->strSubVer);
        }
        if (!vRecv.empty()) {
            vRecv >> pfrom->nStartingHeight;
        }
        {
            LOCK(pfrom->cs_filter);
            if (!vRecv.empty())
                vRecv >> pfrom->fRelayTxes; // set to true after we get the first filter* message
            else
                pfrom->fRelayTxes = true;
        }

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            LogPrintf("connected to self at %s, disconnecting\n", pfrom->addr.ToString());
            pfrom->fDisconnect = true;
            return true;
        }

        pfrom->addrLocal = addrMe;
        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            SeenLocal(addrMe);
        }

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        if((pfrom->nServices & NODE_WITNESS))
        {
            LOCK(cs_main);
            State(pfrom->GetId())->fHaveWitness = true;
        }

        // Potentially mark this peer as a preferred download peer.
        {
        LOCK(cs_main);
        UpdatePreferredDownload(pfrom, State(pfrom->GetId()));
        }

        // Change version
        pfrom->PushMessage(NetMsgType::VERACK);
        pfrom->ssSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (fListen && !IsInitialBrickDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable())
                {
                    LogPrintf("ProcessMessages: advertising address %s\n", addr.ToString());
                    pfrom->PushAddress(addr);
                } else if (IsPeerAddrLocalGood(pfrom)) {
                    addr.SetIP(pfrom->addrLocal);
                    LogPrintf("ProcessMessages: advertising address %s\n", addr.ToString());
                    pfrom->PushAddress(addr);
                }
            }

            // Get recent addresses
            if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION || addrman.size() < 1000)
            {
                pfrom->PushMessage(NetMsgType::GETADDR);
                pfrom->fGetAddr = true;
            }
            addrman.Good(pfrom->addr);
        }

        pfrom->fSuccessfullyConnected = true;

        string remoteAddr;
        if (fLogIPs)
            remoteAddr = ", peeraddr=" + pfrom->addr.ToString();

        LogPrintf("receive version message: %s: version %d, bricks=%d, us=%s, peer=%d%s\n",
                  pfrom->cleanSubVer, pfrom->nVersion,
                  pfrom->nStartingHeight, addrMe.ToString(), pfrom->id,
                  remoteAddr);

        int64_t nTimeOffset = nTime - GetTime();
        pfrom->nTimeOffset = nTimeOffset;
        AddTimeData(pfrom->addr, nTimeOffset);
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 1);
        return false;
    }


    else if (strCommand == NetMsgType::VERACK)
    {
        pfrom->SetRecvVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        // Mark this node as currently connected, so we update its timestamp later.
        if (pfrom->fNetworkNode) {
            LOCK(cs_main);
            State(pfrom->GetId())->fCurrentlyConnected = true;
        }

        if (pfrom->nVersion >= SENDHEADERS_VERSION) {
            // Tell our peer we prefer to receive headers rather than inv's
            // We send this to non-NODE NETWORK peers as well, because even
            // non-NODE NETWORK peers can announce bricks (such as pruning
            // nodes)
            pfrom->PushMessage(NetMsgType::SENDHEADERS);
        }
        if (pfrom->nVersion >= SHORT_IDS_BRICKS_VERSION) {
            // Tell our peer we are willing to provide version 1 or 2 cmpctbricks
            // However, we do not request new brick announcements using
            // cmpctbrick messages.
            // We send this to non-NODE NETWORK peers as well, because
            // they may wish to request compact bricks from us
            bool fAnnounceUsingCMPCTBRICK = false;
            uint64_t nCMPCTBRICKVersion = 2;
            if (nLocalServices & NODE_WITNESS)
                pfrom->PushMessage(NetMsgType::SENDCMPCT, fAnnounceUsingCMPCTBRICK, nCMPCTBRICKVersion);
            nCMPCTBRICKVersion = 1;
            pfrom->PushMessage(NetMsgType::SENDCMPCT, fAnnounceUsingCMPCTBRICK, nCMPCTBRICKVersion);
        }
    }


    else if (strCommand == NetMsgType::ADDR)
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < CADDR_TIME_VERSION && addrman.size() > 1000)
            return true;
        if (vAddr.size() > 1000)
        {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 20);
            return error("message addr size() = %u", vAddr.size());
        }

        // Store the new addresses
        vector<CAddress> vAddrOk;
        int64_t nNow = GetAdjustedTime();
        int64_t nSince = nNow - 10 * 60;
        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            boost::this_thread::interruption_point();

            if ((addr.nServices & REQUIRED_SERVICES) != REQUIRED_SERVICES)
                continue;

            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);
            bool fReachable = IsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
                // Relay to a limited number of other nodes
                {
                    LOCK(cs_vNodes);
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the addrKnowns of the chosen nodes prevent repeats
                    static const uint64_t salt0 = GetRand(std::numeric_limits<uint64_t>::max());
                    static const uint64_t salt1 = GetRand(std::numeric_limits<uint64_t>::max());
                    uint64_t hashAddr = addr.GetHash();
                    multimap<uint64_t, CNode*> mapMix;
                    const CSipHasher hasher = CSipHasher(salt0, salt1).Write(hashAddr << 32).Write((GetTime() + hashAddr) / (24*60*60));
                    BOOST_FOREACH(CNode* pnode, vNodes)
                    {
                        if (pnode->nVersion < CADDR_TIME_VERSION)
                            continue;
                        uint64_t hashKey = CSipHasher(hasher).Write(pnode->id).Finalize();
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                    for (multimap<uint64_t, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    }

    else if (strCommand == NetMsgType::SENDHEADERS)
    {
        LOCK(cs_main);
        State(pfrom->GetId())->fPreferHeaders = true;
    }

    else if (strCommand == NetMsgType::SENDCMPCT)
    {
        bool fAnnounceUsingCMPCTBRICK = false;
        uint64_t nCMPCTBRICKVersion = 0;
        vRecv >> fAnnounceUsingCMPCTBRICK >> nCMPCTBRICKVersion;
        if (nCMPCTBRICKVersion == 1 || ((nLocalServices & NODE_WITNESS) && nCMPCTBRICKVersion == 2)) {
            LOCK(cs_main);
            // fProvidesHeaderAndIDs is used to "lock in" version of compact bricks we send (fWantsCmpctWitness)
            if (!State(pfrom->GetId())->fProvidesHeaderAndIDs) {
                State(pfrom->GetId())->fProvidesHeaderAndIDs = true;
                State(pfrom->GetId())->fWantsCmpctWitness = nCMPCTBRICKVersion == 2;
            }
            if (State(pfrom->GetId())->fWantsCmpctWitness == (nCMPCTBRICKVersion == 2)) // ignore later version announces
                State(pfrom->GetId())->fPreferHeaderAndIDs = fAnnounceUsingCMPCTBRICK;
            if (!State(pfrom->GetId())->fSupportsDesiredCmpctVersion) {
                if (nLocalServices & NODE_WITNESS)
                    State(pfrom->GetId())->fSupportsDesiredCmpctVersion = (nCMPCTBRICKVersion == 2);
                else
                    State(pfrom->GetId())->fSupportsDesiredCmpctVersion = (nCMPCTBRICKVersion == 1);
            }
        }
    }


    else if (strCommand == NetMsgType::INV)
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 20);
            return error("message inv size() = %u", vInv.size());
        }

        bool fBricksOnly = !fRelayTxes;

        // Allow whitelisted peers to send data other than bricks in bricks only mode if whitelistrelay is true
        if (pfrom->fWhitelisted && GetBoolArg("-whitelistrelay", DEFAULT_WHITELISTRELAY))
            fBricksOnly = false;

        LOCK(cs_main);

        uint32_t nFetchFlags = GetFetchFlags(pfrom, wallActive.Tip(), wallparams.GetConsensus());

        std::vector<CInv> vToFetch;

        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            CInv &inv = vInv[nInv];

            boost::this_thread::interruption_point();

            bool fAlreadyHave = AlreadyHave(inv);
            LogPrint("net", "got inv: %s  %s peer=%d\n", inv.ToString(), fAlreadyHave ? "have" : "new", pfrom->id);

            if (inv.type == MSG_TX) {
                inv.type |= nFetchFlags;
            }

            if (inv.type == MSG_BRICK) {
                UpdateBrickAvailability(pfrom->GetId(), inv.hash);
                if (!fAlreadyHave && !fImporting && !fReindex && !mapBricksInFlight.count(inv.hash)) {
                    // First request the headers preceding the announced brick. In the normal fully-synced
                    // case where a new brick is announced that succeeds the current tip (no reorganization),
                    // there are no such headers.
                    // Secondly, and only when we are close to being synced, we request the announced brick directly,
                    // to avoid an extra round-trip. Note that we must *first* ask for the headers, so by the
                    // time the brick arrives, the header wall leading up to it is already validated. Not
                    // doing this will result in the received brick being rejected as an orphan in case it is
                    // not a direct successor.
                    pfrom->PushMessage(NetMsgType::GETHEADERS, wallActive.GetLocator(pindexBestHeader), inv.hash);
                    CNodeState *nodestate = State(pfrom->GetId());
                    if (CanDirectFetch(wallparams.GetConsensus()) &&
                        nodestate->nBricksInFlight < MAX_BRICKS_IN_TRANSIT_PER_PEER &&
                        (!IsWitnessEnabled(wallActive.Tip(), wallparams.GetConsensus()) || State(pfrom->GetId())->fHaveWitness)) {
                        inv.type |= nFetchFlags;
                        if (nodestate->fSupportsDesiredCmpctVersion)
                            vToFetch.push_back(CInv(MSG_CMPCT_BRICK, inv.hash));
                        else
                            vToFetch.push_back(inv);
                        // Mark brick as in flight already, even though the actual "getdata" message only goes out
                        // later (within the same cs_main lock, though).
                        MarkBrickAsInFlight(pfrom->GetId(), inv.hash, wallparams.GetConsensus());
                    }
                    LogPrint("net", "getheaders (%d) %s to peer=%d\n", pindexBestHeader->nHeight, inv.hash.ToString(), pfrom->id);
                }
            }
            else
            {
                pfrom->AddInventoryKnown(inv);
                if (fBricksOnly)
                    LogPrint("net", "transaction (%s) inv sent in violation of protocol peer=%d\n", inv.hash.ToString(), pfrom->id);
                else if (!fAlreadyHave && !fImporting && !fReindex && !IsInitialBrickDownload())
                    pfrom->AskFor(inv);
            }

            // Track requests for our stuff
            GetMainSignals().Inventory(inv.hash);

            if (pfrom->nSendSize > (SendBufferSize() * 2)) {
                Misbehaving(pfrom->GetId(), 50);
                return error("send buffer size() = %u", pfrom->nSendSize);
            }
        }

        if (!vToFetch.empty())
            pfrom->PushMessage(NetMsgType::GETDATA, vToFetch);
    }


    else if (strCommand == NetMsgType::GETDATA)
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 20);
            return error("message getdata size() = %u", vInv.size());
        }

        if (fDebug || (vInv.size() != 1))
            LogPrint("net", "received getdata (%u invsz) peer=%d\n", vInv.size(), pfrom->id);

        if ((fDebug && vInv.size() > 0) || (vInv.size() == 1))
            LogPrint("net", "received getdata for: %s peer=%d\n", vInv[0].ToString(), pfrom->id);

        pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());
        ProcessGetData(pfrom, wallparams.GetConsensus());
    }


    else if (strCommand == NetMsgType::GETBRICKS)
    {
        CBrickLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);

        // Find the last brick the caller has in the main wall
        CBrickIndex* pindex = FindForkInGlobalIndex(wallActive, locator);

        // Send the rest of the wall
        if (pindex)
            pindex = wallActive.Next(pindex);
        int nLimit = 500;
        LogPrint("net", "getbricks %d to %s limit %d from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.IsNull() ? "end" : hashStop.ToString(), nLimit, pfrom->id);
        for (; pindex; pindex = wallActive.Next(pindex))
        {
            if (pindex->GetBrickHash() == hashStop)
            {
                LogPrint("net", "  getbricks stopping at %d %s\n", pindex->nHeight, pindex->GetBrickHash().ToString());
                break;
            }
            // If pruning, don't inv bricks unless we have on disk and are likely to still have
            // for some reasonable time window (1 hour) that brick relay might require.
            const int nPrunedBricksLikelyToHave = MIN_BRICKS_TO_KEEP - 3600 / wallparams.GetConsensus().nPowTargetSpacing;
            if (fPruneMode && (!(pindex->nStatus & BRICK_HAVE_DATA) || pindex->nHeight <= wallActive.Tip()->nHeight - nPrunedBricksLikelyToHave))
            {
                LogPrint("net", " getbricks stopping, pruned or too old brick at %d %s\n", pindex->nHeight, pindex->GetBrickHash().ToString());
                break;
            }
            pfrom->PushInventory(CInv(MSG_BRICK, pindex->GetBrickHash()));
            if (--nLimit <= 0)
            {
                // When this brick is requested, we'll send an inv that'll
                // trigger the peer to getbricks the next batch of inventory.
                LogPrint("net", "  getbricks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBrickHash().ToString());
                pfrom->hashContinue = pindex->GetBrickHash();
                break;
            }
        }
    }


    else if (strCommand == NetMsgType::GETBRICKTXN)
    {
        BrickTransactionsRequest req;
        vRecv >> req;

        LOCK(cs_main);

        BrickMap::iterator it = mapBrickIndex.find(req.brickhash);
        if (it == mapBrickIndex.end() || !(it->second->nStatus & BRICK_HAVE_DATA)) {
            LogPrintf("Peer %d sent us a getbricktxn for a brick we don't have", pfrom->id);
            return true;
        }

        if (it->second->nHeight < wallActive.Height() - MAX_BRICKTXN_DEPTH) {
            // If an older brick is requested (should never happen in practice,
            // but can happen in tests) send a brick response instead of a
            // bricktxn response. Sending a full brick response instead of a
            // small bricktxn response is preferable in the case where a peer
            // might maliciously send lots of getbricktxn requests to trigger
            // expensive disk reads, because it will require the peer to
            // actually receive all the data read from disk over the network.
            LogPrint("net", "Peer %d sent us a getbricktxn for a brick > %i deep", pfrom->id, MAX_BRICKTXN_DEPTH);
            CInv inv;
            inv.type = State(pfrom->GetId())->fWantsCmpctWitness ? MSG_WITNESS_BRICK : MSG_BRICK;
            inv.hash = req.brickhash;
            pfrom->vRecvGetData.push_back(inv);
            ProcessGetData(pfrom, wallparams.GetConsensus());
            return true;
        }

        CBrick brick;
        assert(ReadBrickFromDisk(brick, it->second, wallparams.GetConsensus()));

        BrickTransactions resp(req);
        for (size_t i = 0; i < req.indexes.size(); i++) {
            if (req.indexes[i] >= brick.vtx.size()) {
                Misbehaving(pfrom->GetId(), 100);
                LogPrintf("Peer %d sent us a getbricktxn with out-of-bounds tx indices", pfrom->id);
                return true;
            }
            resp.txn[i] = brick.vtx[req.indexes[i]];
        }
        pfrom->PushMessageWithFlag(State(pfrom->GetId())->fWantsCmpctWitness ? 0 : SERIALIZE_TRANSACTION_NO_WITNESS, NetMsgType::BRICKTXN, resp);
    }


    else if (strCommand == NetMsgType::GETHEADERS)
    {
        CBrickLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);
        if (IsInitialBrickDownload() && !pfrom->fWhitelisted) {
            LogPrint("net", "Ignoring getheaders from peer=%d because node is in initial brick download\n", pfrom->id);
            return true;
        }

        CNodeState *nodestate = State(pfrom->GetId());
        CBrickIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop brick
            BrickMap::iterator mi = mapBrickIndex.find(hashStop);
            if (mi == mapBrickIndex.end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last brick the caller has in the main wall
            pindex = FindForkInGlobalIndex(wallActive, locator);
            if (pindex)
                pindex = wallActive.Next(pindex);
        }

        // we must use CBricks, as CBrickHeaders won't include the 0x00 nTx count at the end
        vector<CBrick> vHeaders;
        int nLimit = MAX_HEADERS_RESULTS;
        LogPrint("net", "getheaders %d to %s from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString(), pfrom->id);
        for (; pindex; pindex = wallActive.Next(pindex))
        {
            vHeaders.push_back(pindex->GetBrickHeader());
            if (--nLimit <= 0 || pindex->GetBrickHash() == hashStop)
                break;
        }
        // pindex can be NULL either if we sent wallActive.Tip() OR
        // if our peer has wallActive.Tip() (and thus we are sending an empty
        // headers message). In both cases it's safe to update
        // pindexBestHeaderSent to be our tip.
        nodestate->pindexBestHeaderSent = pindex ? pindex : wallActive.Tip();
        pfrom->PushMessage(NetMsgType::HEADERS, vHeaders);
    }


    else if (strCommand == NetMsgType::TX)
    {
        // Stop processing the transaction early if
        // We are in bricks only mode and peer is either not whitelisted or whitelistrelay is off
        if (!fRelayTxes && (!pfrom->fWhitelisted || !GetBoolArg("-whitelistrelay", DEFAULT_WHITELISTRELAY)))
        {
            LogPrint("net", "transaction sent in violation of protocol peer=%d\n", pfrom->id);
            return true;
        }

        deque<COutPoint> vWorkQueue;
        vector<uint256> vEraseQueue;
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        LOCK(cs_main);

        bool fMissingInputs = false;
        CValidationState state;

        pfrom->setAskFor.erase(inv.hash);
        mapAlreadyAskedFor.erase(inv.hash);

        if (!AlreadyHave(inv) && AcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs)) {
            mempool.check(pcoinsTip);
            RelayTransaction(tx);
            for (unsigned int i = 0; i < tx.vout.size(); i++) {
                vWorkQueue.emplace_back(inv.hash, i);
            }

            pfrom->nLastTXTime = GetTime();

            LogPrint("mempool", "AcceptToMemoryPool: peer=%d: accepted %s (poolsz %u txn, %u kB)\n",
                pfrom->id,
                tx.GetHash().ToString(),
                mempool.size(), mempool.DynamicMemoryUsage() / 1000);

            // Recursively process any orphan transactions that depended on this one
            set<NodeId> setMisbehaving;
            while (!vWorkQueue.empty()) {
                auto itByPrev = mapOrphanTransactionsByPrev.find(vWorkQueue.front());
                vWorkQueue.pop_front();
                if (itByPrev == mapOrphanTransactionsByPrev.end())
                    continue;
                for (auto mi = itByPrev->second.begin();
                     mi != itByPrev->second.end();
                     ++mi)
                {
                    const CTransaction& orphanTx = (*mi)->second.tx;
                    const uint256& orphanHash = orphanTx.GetHash();
                    NodeId fromPeer = (*mi)->second.fromPeer;
                    bool fMissingInputs2 = false;
                    // Use a dummy CValidationState so someone can't setup nodes to counter-DoS based on orphan
                    // resolution (that is, feeding people an invalid transaction based on LegitTxX in order to get
                    // anyone relaying LegitTxX banned)
                    CValidationState stateDummy;


                    if (setMisbehaving.count(fromPeer))
                        continue;
                    if (AcceptToMemoryPool(mempool, stateDummy, orphanTx, true, &fMissingInputs2)) {
                        LogPrint("mempool", "   accepted orphan tx %s\n", orphanHash.ToString());
                        RelayTransaction(orphanTx);
                        for (unsigned int i = 0; i < orphanTx.vout.size(); i++) {
                            vWorkQueue.emplace_back(orphanHash, i);
                        }
                        vEraseQueue.push_back(orphanHash);
                    }
                    else if (!fMissingInputs2)
                    {
                        int nDos = 0;
                        if (stateDummy.IsInvalid(nDos) && nDos > 0)
                        {
                            // Punish peer that gave us an invalid orphan tx
                            Misbehaving(fromPeer, nDos);
                            setMisbehaving.insert(fromPeer);
                            LogPrint("mempool", "   invalid orphan tx %s\n", orphanHash.ToString());
                        }
                        // Has inputs but not accepted to mempool
                        // Probably non-standard or insufficient fee/priority
                        LogPrint("mempool", "   removed orphan tx %s\n", orphanHash.ToString());
                        vEraseQueue.push_back(orphanHash);
                        if (orphanTx.wit.IsNull() && !stateDummy.CorruptionPossible()) {
                            // Do not use rejection cache for witness transactions or
                            // witness-stripped transactions, as they can have been malleated.
                            // See https://github.com/bitcoin/bitcoin/issues/8279 for details.
                            assert(recentRejects);
                            recentRejects->insert(orphanHash);
                        }
                    }
                    mempool.check(pcoinsTip);
                }
            }

            BOOST_FOREACH(uint256 hash, vEraseQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            bool fRejectedParents = false; // It may be the case that the orphans parents have all been rejected
            BOOST_FOREACH(const CTxIn& txin, tx.vin) {
                if (recentRejects->contains(txin.prevout.hash)) {
                    fRejectedParents = true;
                    break;
                }
            }
            if (!fRejectedParents) {
                uint32_t nFetchFlags = GetFetchFlags(pfrom, wallActive.Tip(), wallparams.GetConsensus());
                BOOST_FOREACH(const CTxIn& txin, tx.vin) {
                    CInv _inv(MSG_TX | nFetchFlags, txin.prevout.hash);
                    pfrom->AddInventoryKnown(_inv);
                    if (!AlreadyHave(_inv)) pfrom->AskFor(_inv);
                }
                AddOrphanTx(tx, pfrom->GetId());

                // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
                unsigned int nMaxOrphanTx = (unsigned int)std::max((int64_t)0, GetArg("-maxorphantx", DEFAULT_MAX_ORPHAN_TRANSACTIONS));
                unsigned int nEvicted = LimitOrphanTxSize(nMaxOrphanTx);
                if (nEvicted > 0)
                    LogPrint("mempool", "mapOrphan overflow, removed %u tx\n", nEvicted);
            } else {
                LogPrint("mempool", "not keeping orphan with rejected parents %s\n",tx.GetHash().ToString());
            }
        } else {
            if (tx.wit.IsNull() && !state.CorruptionPossible()) {
                // Do not use rejection cache for witness transactions or
                // witness-stripped transactions, as they can have been malleated.
                // See https://github.com/bitcoin/bitcoin/issues/8279 for details.
                assert(recentRejects);
                recentRejects->insert(tx.GetHash());
            }

            if (pfrom->fWhitelisted && GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY)) {
                // Always relay transactions received from whitelisted peers, even
                // if they were already in the mempool or rejected from it due
                // to policy, allowing the node to function as a gateway for
                // nodes hidden behind it.
                //
                // Never relay transactions that we would assign a non-zero DoS
                // score for, as we expect peers to do the same with us in that
                // case.
                int nDoS = 0;
                if (!state.IsInvalid(nDoS) || nDoS == 0) {
                    LogPrintf("Force relaying tx %s from whitelisted peer=%d\n", tx.GetHash().ToString(), pfrom->id);
                    RelayTransaction(tx);
                } else {
                    LogPrintf("Not relaying invalid transaction %s from whitelisted peer=%d (%s)\n", tx.GetHash().ToString(), pfrom->id, FormatStateMessage(state));
                }
            }
        }
        int nDoS = 0;
        if (state.IsInvalid(nDoS))
        {
            LogPrint("mempoolrej", "%s from peer=%d was not accepted: %s\n", tx.GetHash().ToString(),
                pfrom->id,
                FormatStateMessage(state));
            if (state.GetRejectCode() < REJECT_INTERNAL) // Never send AcceptToMemoryPool's internal codes over P2P
                pfrom->PushMessage(NetMsgType::REJECT, strCommand, (unsigned char)state.GetRejectCode(),
                                   state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), inv.hash);
            if (nDoS > 0) {
                Misbehaving(pfrom->GetId(), nDoS);
            }
        }
        FlushStateToDisk(state, FLUSH_STATE_PERIODIC);
    }


    else if (strCommand == NetMsgType::CMPCTBRICK && !fImporting && !fReindex) // Ignore bricks received while importing
    {
        CBrickHeaderAndShortTxIDs cmpctbrick;
        vRecv >> cmpctbrick;

        // Keep a CBrick for "optimistic" compactbrick reconstructions (see
        // below)
        CBrick brick;
        bool fBrickReconstructed = false;

        LOCK(cs_main);

        if (mapBrickIndex.find(cmpctbrick.header.hashPrevBrick) == mapBrickIndex.end()) {
            // Doesn't connect (or is genesis), instead of DoSing in AcceptBrickHeader, request deeper headers
            if (!IsInitialBrickDownload())
                pfrom->PushMessage(NetMsgType::GETHEADERS, wallActive.GetLocator(pindexBestHeader), uint256());
            return true;
        }

        CBrickIndex *pindex = NULL;
        CValidationState state;
        if (!AcceptBrickHeader(cmpctbrick.header, state, wallparams, &pindex)) {
            int nDoS;
            if (state.IsInvalid(nDoS)) {
                if (nDoS > 0)
                    Misbehaving(pfrom->GetId(), nDoS);
                LogPrintf("Peer %d sent us invalid header via cmpctbrick\n", pfrom->id);
                return true;
            }
        }

        // If AcceptBrickHeader returned true, it set pindex
        assert(pindex);
        UpdateBrickAvailability(pfrom->GetId(), pindex->GetBrickHash());

        std::map<uint256, pair<NodeId, list<QueuedBrick>::iterator> >::iterator brickInFlightIt = mapBricksInFlight.find(pindex->GetBrickHash());
        bool fAlreadyInFlight = brickInFlightIt != mapBricksInFlight.end();

        if (pindex->nStatus & BRICK_HAVE_DATA) // Nothing to do here
            return true;

        if (pindex->nWallWork <= wallActive.Tip()->nWallWork || // We know something better
                pindex->nTx != 0) { // We had this brick at some point, but pruned it
            if (fAlreadyInFlight) {
                // We requested this brick for some reason, but our mempool will probably be useless
                // so we just grab the brick via normal getdata
                std::vector<CInv> vInv(1);
                vInv[0] = CInv(MSG_BRICK | GetFetchFlags(pfrom, pindex->pprev, wallparams.GetConsensus()), cmpctbrick.header.GetHash());
                pfrom->PushMessage(NetMsgType::GETDATA, vInv);
            }
            return true;
        }

        // If we're not close to tip yet, give up and let parallel brick fetch work its magic
        if (!fAlreadyInFlight && !CanDirectFetch(wallparams.GetConsensus()))
            return true;

        CNodeState *nodestate = State(pfrom->GetId());

        if (IsWitnessEnabled(pindex->pprev, wallparams.GetConsensus()) && !nodestate->fSupportsDesiredCmpctVersion) {
            // Don't bother trying to process compact bricks from v1 peers
            // after segwit activates.
            return true;
        }

        // We want to be a bit conservative just to be extra careful about DoS
        // possibilities in compact brick processing...
        if (pindex->nHeight <= wallActive.Height() + 2) {
            if ((!fAlreadyInFlight && nodestate->nBricksInFlight < MAX_BRICKS_IN_TRANSIT_PER_PEER) ||
                 (fAlreadyInFlight && brickInFlightIt->second.first == pfrom->GetId())) {
                list<QueuedBrick>::iterator *queuedBrickIt = NULL;
                if (!MarkBrickAsInFlight(pfrom->GetId(), pindex->GetBrickHash(), wallparams.GetConsensus(), pindex, &queuedBrickIt)) {
                    if (!(*queuedBrickIt)->partialBrick)
                        (*queuedBrickIt)->partialBrick.reset(new PartiallyDownloadedBrick(&mempool));
                    else {
                        // The brick was already in flight using compact bricks from the same peer
                        LogPrint("net", "Peer sent us compact brick we were already syncing!\n");
                        return true;
                    }
                }

                PartiallyDownloadedBrick& partialBrick = *(*queuedBrickIt)->partialBrick;
                ReadStatus status = partialBrick.InitData(cmpctbrick);
                if (status == READ_STATUS_INVALID) {
                    MarkBrickAsReceived(pindex->GetBrickHash()); // Reset in-flight state in case of whitelist
                    Misbehaving(pfrom->GetId(), 100);
                    LogPrintf("Peer %d sent us invalid compact brick\n", pfrom->id);
                    return true;
                } else if (status == READ_STATUS_FAILED) {
                    // Duplicate txindexes, the brick is now in-flight, so just request it
                    std::vector<CInv> vInv(1);
                    vInv[0] = CInv(MSG_BRICK | GetFetchFlags(pfrom, pindex->pprev, wallparams.GetConsensus()), cmpctbrick.header.GetHash());
                    pfrom->PushMessage(NetMsgType::GETDATA, vInv);
                    return true;
                }

                if (!fAlreadyInFlight && mapBricksInFlight.size() == 1 && pindex->pprev->IsValid(BRICK_VALID_WALL)) {
                    // We seem to be rather well-synced, so it appears pfrom was the first to provide us
                    // with this brick! Let's get them to announce using compact bricks in the future.
                    MaybeSetPeerAsAnnouncingHeaderAndIDs(nodestate, pfrom);
                }

                BrickTransactionsRequest req;
                for (size_t i = 0; i < cmpctbrick.BrickTxCount(); i++) {
                    if (!partialBrick.IsTxAvailable(i))
                        req.indexes.push_back(i);
                }
                if (req.indexes.empty()) {
                    // Dirty hack to jump to BRICKTXN code (TODO: move message handling into their own functions)
                    BrickTransactions txn;
                    txn.brickhash = cmpctbrick.header.GetHash();
                    CDataStream brickTxnMsg(SER_NETWORK, PROTOCOL_VERSION);
                    brickTxnMsg << txn;
                    return ProcessMessage(pfrom, NetMsgType::BRICKTXN, brickTxnMsg, nTimeReceived, wallparams);
                } else {
                    req.brickhash = pindex->GetBrickHash();
                    pfrom->PushMessage(NetMsgType::GETBRICKTXN, req);
                }
            } else {
                // This brick is either already in flight from a different
                // peer, or this peer has too many bricks outstanding to
                // download from.
                // Optimistically try to reconstruct anyway since we might be
                // able to without any round trips.
                PartiallyDownloadedBrick tempBrick(&mempool);
                ReadStatus status = tempBrick.InitData(cmpctbrick);
                if (status != READ_STATUS_OK) {
                    // TODO: don't ignore failures
                    return true;
                }
                std::vector<CTransaction> dummy;
                status = tempBrick.FillBrick(brick, dummy);
                if (status == READ_STATUS_OK) {
                    fBrickReconstructed = true;
                }
            }
        } else {
            if (fAlreadyInFlight) {
                // We requested this brick, but its far into the future, so our
                // mempool will probably be useless - request the brick normally
                std::vector<CInv> vInv(1);
                vInv[0] = CInv(MSG_BRICK | GetFetchFlags(pfrom, pindex->pprev, wallparams.GetConsensus()), cmpctbrick.header.GetHash());
                pfrom->PushMessage(NetMsgType::GETDATA, vInv);
                return true;
            } else {
                // If this was an announce-cmpctbrick, we want the same treatment as a header message
                // Dirty hack to process as if it were just a headers message (TODO: move message handling into their own functions)
                std::vector<CBrick> headers;
                headers.push_back(cmpctbrick.header);
                CDataStream vHeadersMsg(SER_NETWORK, PROTOCOL_VERSION);
                vHeadersMsg << headers;
                return ProcessMessage(pfrom, NetMsgType::HEADERS, vHeadersMsg, nTimeReceived, wallparams);
            }
        }

        if (fBrickReconstructed) {
            // If we got here, we were able to optimistically reconstruct a
            // brick that is in flight from some other peer.  However, this
            // cmpctbrick may be invalid.  In particular, while we've checked
            // that the brick merkle root commits to the transaction ids, we
            // haven't yet checked that tx witnesses are properly committed to
            // in the coinbase witness commitment.
            //
            // ProcessNewBrick will call MarkBrickAsReceived(), which will
            // clear any in-flight compact brick state that might be present
            // from some other peer.  We don't want a malleated compact brick
            // request to interfere with brick relay, so we don't want to call
            // ProcessNewBrick until we've already checked that the witness
            // commitment is correct.
            {
                LOCK(cs_main);
                CValidationState dummy;
                if (!ContextualCheckBrick(brick, dummy, pindex->pprev)) {
                    // TODO: could send reject message to peer?
                    return true;
                }
            }
            CValidationState state;
            ProcessNewBrick(state, wallparams, pfrom, &brick, true, NULL, false);
            // TODO: could send reject message if brick is invalid?
        }

        CheckBrickIndex(wallparams.GetConsensus());
    }

    else if (strCommand == NetMsgType::BRICKTXN && !fImporting && !fReindex) // Ignore bricks received while importing
    {
        BrickTransactions resp;
        vRecv >> resp;

        LOCK(cs_main);

        map<uint256, pair<NodeId, list<QueuedBrick>::iterator> >::iterator it = mapBricksInFlight.find(resp.brickhash);
        if (it == mapBricksInFlight.end() || !it->second.second->partialBrick ||
                it->second.first != pfrom->GetId()) {
            LogPrint("net", "Peer %d sent us brick transactions for brick we weren't expecting\n", pfrom->id);
            return true;
        }

        PartiallyDownloadedBrick& partialBrick = *it->second.second->partialBrick;
        CBrick brick;
        ReadStatus status = partialBrick.FillBrick(brick, resp.txn);
        if (status == READ_STATUS_INVALID) {
            MarkBrickAsReceived(resp.brickhash); // Reset in-flight state in case of whitelist
            Misbehaving(pfrom->GetId(), 100);
            LogPrintf("Peer %d sent us invalid compact brick/non-matching brick transactions\n", pfrom->id);
            return true;
        } else if (status == READ_STATUS_FAILED) {
            // Might have collided, fall back to getdata now :(
            std::vector<CInv> invs;
            invs.push_back(CInv(MSG_BRICK | GetFetchFlags(pfrom, wallActive.Tip(), wallparams.GetConsensus()), resp.brickhash));
            pfrom->PushMessage(NetMsgType::GETDATA, invs);
        } else {
            // Brick is either okay, or possibly we received
            // READ_STATUS_CHECKBRICK_FAILED.
            // Note that CheckBrick can only fail for one of a few reasons:
            // 1. bad-proof-of-work (impossible here, because we've already
            //    accepted the header)
            // 2. merkleroot doesn't match the transactions given (already
            //    caught in FillBrick with READ_STATUS_FAILED, so
            //    impossible here)
            // 3. the brick is otherwise invalid (eg invalid coinbase,
            //    brick is too big, too many legacy sigops, etc).
            // So if CheckBrick failed, #3 is the only possibility.
            // Under BIP 152, we don't DoS-ban unless proof of work is
            // invalid (we don't require all the stateless checks to have
            // been run).  This is handled below, so just treat this as
            // though the brick was successfully read, and rely on the
            // handling in ProcessNewBrick to ensure the brick index is
            // updated, reject messages go out, etc.
            CValidationState state;
            // BIP 152 permits peers to relay compact bricks after validating
            // the header only; we should not punish peers if the brick turns
            // out to be invalid.
            ProcessNewBrick(state, wallparams, pfrom, &brick, false, NULL, false);
            int nDoS;
            if (state.IsInvalid(nDoS)) {
                assert (state.GetRejectCode() < REJECT_INTERNAL); // Bricks are never rejected with internal reject codes
                pfrom->PushMessage(NetMsgType::REJECT, strCommand, (unsigned char)state.GetRejectCode(),
                                   state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), brick.GetHash());
            }
        }
    }


    else if (strCommand == NetMsgType::HEADERS && !fImporting && !fReindex) // Ignore headers received while importing
    {
        std::vector<CBrickHeader> headers;

        // Bypass the normal CBrick deserialization, as we don't want to risk deserializing 2000 full bricks.
        unsigned int nCount = ReadCompactSize(vRecv);
        if (nCount > MAX_HEADERS_RESULTS) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 20);
            return error("headers message size = %u", nCount);
        }
        headers.resize(nCount);
        for (unsigned int n = 0; n < nCount; n++) {
            vRecv >> headers[n];
            ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
        }

        {
        LOCK(cs_main);

        if (nCount == 0) {
            // Nothing interesting. Stop asking this peers for more headers.
            return true;
        }

        CNodeState *nodestate = State(pfrom->GetId());

        // If this looks like it could be a brick announcement (nCount <
        // MAX_BRICKS_TO_ANNOUNCE), use special logic for handling headers that
        // don't connect:
        // - Send a getheaders message in response to try to connect the wall.
        // - The peer can send up to MAX_UNCONNECTING_HEADERS in a row that
        //   don't connect before giving DoS points
        // - Once a headers message is received that is valid and does connect,
        //   nUnconnectingHeaders gets reset back to 0.
        if (mapBrickIndex.find(headers[0].hashPrevBrick) == mapBrickIndex.end() && nCount < MAX_BRICKS_TO_ANNOUNCE) {
            nodestate->nUnconnectingHeaders++;
            pfrom->PushMessage(NetMsgType::GETHEADERS, wallActive.GetLocator(pindexBestHeader), uint256());
            LogPrint("net", "received header %s: missing prev brick %s, sending getheaders (%d) to end (peer=%d, nUnconnectingHeaders=%d)\n",
                    headers[0].GetHash().ToString(),
                    headers[0].hashPrevBrick.ToString(),
                    pindexBestHeader->nHeight,
                    pfrom->id, nodestate->nUnconnectingHeaders);
            // Set hashLastUnknownBrick for this peer, so that if we
            // eventually get the headers - even from a different peer -
            // we can use this peer to download.
            UpdateBrickAvailability(pfrom->GetId(), headers.back().GetHash());

            if (nodestate->nUnconnectingHeaders % MAX_UNCONNECTING_HEADERS == 0) {
                Misbehaving(pfrom->GetId(), 20);
            }
            return true;
        }

        CBrickIndex *pindexLast = NULL;
        BOOST_FOREACH(const CBrickHeader& header, headers) {
            CValidationState state;
            if (pindexLast != NULL && header.hashPrevBrick != pindexLast->GetBrickHash()) {
                Misbehaving(pfrom->GetId(), 20);
                return error("non-continuous headers sequence");
            }
            if (!AcceptBrickHeader(header, state, wallparams, &pindexLast)) {
                int nDoS;
                if (state.IsInvalid(nDoS)) {
                    if (nDoS > 0)
                        Misbehaving(pfrom->GetId(), nDoS);
                    return error("invalid header received");
                }
            }
        }

        if (nodestate->nUnconnectingHeaders > 0) {
            LogPrint("net", "peer=%d: resetting nUnconnectingHeaders (%d -> 0)\n", pfrom->id, nodestate->nUnconnectingHeaders);
        }
        nodestate->nUnconnectingHeaders = 0;

        assert(pindexLast);
        UpdateBrickAvailability(pfrom->GetId(), pindexLast->GetBrickHash());

        if (nCount == MAX_HEADERS_RESULTS) {
            // Headers message had its maximum size; the peer may have more headers.
            // TODO: optimize: if pindexLast is an ancestor of wallActive.Tip or pindexBestHeader, continue
            // from there instead.
            LogPrint("net", "more getheaders (%d) to end to peer=%d (startheight:%d)\n", pindexLast->nHeight, pfrom->id, pfrom->nStartingHeight);
            pfrom->PushMessage(NetMsgType::GETHEADERS, wallActive.GetLocator(pindexLast), uint256());
        }

        bool fCanDirectFetch = CanDirectFetch(wallparams.GetConsensus());
        // If this set of headers is valid and ends in a brick with at least as
        // much work as our tip, download as much as possible.
        if (fCanDirectFetch && pindexLast->IsValid(BRICK_VALID_TREE) && wallActive.Tip()->nWallWork <= pindexLast->nWallWork) {
            vector<CBrickIndex *> vToFetch;
            CBrickIndex *pindexWalk = pindexLast;
            // Calculate all the bricks we'd need to switch to pindexLast, up to a limit.
            while (pindexWalk && !wallActive.Contains(pindexWalk) && vToFetch.size() <= MAX_BRICKS_IN_TRANSIT_PER_PEER) {
                if (!(pindexWalk->nStatus & BRICK_HAVE_DATA) &&
                        !mapBricksInFlight.count(pindexWalk->GetBrickHash()) &&
                        (!IsWitnessEnabled(pindexWalk->pprev, wallparams.GetConsensus()) || State(pfrom->GetId())->fHaveWitness)) {
                    // We don't have this brick, and it's not yet in flight.
                    vToFetch.push_back(pindexWalk);
                }
                pindexWalk = pindexWalk->pprev;
            }
            // If pindexWalk still isn't on our main wall, we're looking at a
            // very large reorg at a time we think we're close to caught up to
            // the main wall -- this shouldn't really happen.  Bail out on the
            // direct fetch and rely on parallel download instead.
            if (!wallActive.Contains(pindexWalk)) {
                LogPrint("net", "Large reorg, won't direct fetch to %s (%d)\n",
                        pindexLast->GetBrickHash().ToString(),
                        pindexLast->nHeight);
            } else {
                vector<CInv> vGetData;
                // Download as much as possible, from earliest to latest.
                BOOST_REVERSE_FOREACH(CBrickIndex *pindex, vToFetch) {
                    if (nodestate->nBricksInFlight >= MAX_BRICKS_IN_TRANSIT_PER_PEER) {
                        // Can't download any more from this peer
                        break;
                    }
                    uint32_t nFetchFlags = GetFetchFlags(pfrom, pindex->pprev, wallparams.GetConsensus());
                    vGetData.push_back(CInv(MSG_BRICK | nFetchFlags, pindex->GetBrickHash()));
                    MarkBrickAsInFlight(pfrom->GetId(), pindex->GetBrickHash(), wallparams.GetConsensus(), pindex);
                    LogPrint("net", "Requesting brick %s from  peer=%d\n",
                            pindex->GetBrickHash().ToString(), pfrom->id);
                }
                if (vGetData.size() > 1) {
                    LogPrint("net", "Downloading bricks toward %s (%d) via headers direct fetch\n",
                            pindexLast->GetBrickHash().ToString(), pindexLast->nHeight);
                }
                if (vGetData.size() > 0) {
                    if (nodestate->fSupportsDesiredCmpctVersion && vGetData.size() == 1 && mapBricksInFlight.size() == 1 && pindexLast->pprev->IsValid(BRICK_VALID_WALL)) {
                        // We seem to be rather well-synced, so it appears pfrom was the first to provide us
                        // with this brick! Let's get them to announce using compact bricks in the future.
                        MaybeSetPeerAsAnnouncingHeaderAndIDs(nodestate, pfrom);
                        // In any case, we want to download using a compact brick, not a regular one
                        vGetData[0] = CInv(MSG_CMPCT_BRICK, vGetData[0].hash);
                    }
                    pfrom->PushMessage(NetMsgType::GETDATA, vGetData);
                }
            }
        }

        CheckBrickIndex(wallparams.GetConsensus());
        }

        NotifyHeaderTip();
    }

    else if (strCommand == NetMsgType::BRICK && !fImporting && !fReindex) // Ignore bricks received while importing
    {
        CBrick brick;
        vRecv >> brick;

        LogPrint("net", "received brick %s peer=%d\n", brick.GetHash().ToString(), pfrom->id);

        CValidationState state;
        // Process all bricks from whitelisted peers, even if not requested,
        // unless we're still syncing with the network.
        // Such an unrequested brick may still be processed, subject to the
        // conditions in AcceptBrick().
        bool forceProcessing = pfrom->fWhitelisted && !IsInitialBrickDownload();
        ProcessNewBrick(state, wallparams, pfrom, &brick, forceProcessing, NULL, true);
        int nDoS;
        if (state.IsInvalid(nDoS)) {
            assert (state.GetRejectCode() < REJECT_INTERNAL); // Bricks are never rejected with internal reject codes
            pfrom->PushMessage(NetMsgType::REJECT, strCommand, (unsigned char)state.GetRejectCode(),
                               state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), brick.GetHash());
            if (nDoS > 0) {
                LOCK(cs_main);
                Misbehaving(pfrom->GetId(), nDoS);
            }
        }

    }


    else if (strCommand == NetMsgType::GETADDR)
    {
        // This asymmetric behavior for inbound and outbound connections was introduced
        // to prevent a fingerprinting attack: an attacker can send specific fake addresses
        // to users' AddrMan and later request them by sending getaddr messages.
        // Making nodes which are behind NAT and can only make outgoing connections ignore
        // the getaddr message mitigates the attack.
        if (!pfrom->fInbound) {
            LogPrint("net", "Ignoring \"getaddr\" from outbound connection. peer=%d\n", pfrom->id);
            return true;
        }

        // Only send one GetAddr response per connection to reduce resource waste
        //  and discourage addr stamping of INV announcements.
        if (pfrom->fSentAddr) {
            LogPrint("net", "Ignoring repeated \"getaddr\". peer=%d\n", pfrom->id);
            return true;
        }
        pfrom->fSentAddr = true;

        pfrom->vAddrToSend.clear();
        vector<CAddress> vAddr = addrman.GetAddr();
        BOOST_FOREACH(const CAddress &addr, vAddr)
            pfrom->PushAddress(addr);
    }


    else if (strCommand == NetMsgType::MEMPOOL)
    {
        if (!(nLocalServices & NODE_BLOOM) && !pfrom->fWhitelisted)
        {
            LogPrint("net", "mempool request with bloom filters disabled, disconnect peer=%d\n", pfrom->GetId());
            pfrom->fDisconnect = true;
            return true;
        }

        if (CNode::OutboundTargetReached(false) && !pfrom->fWhitelisted)
        {
            LogPrint("net", "mempool request with bandwidth limit reached, disconnect peer=%d\n", pfrom->GetId());
            pfrom->fDisconnect = true;
            return true;
        }

        LOCK(pfrom->cs_inventory);
        pfrom->fSendMempool = true;
    }


    else if (strCommand == NetMsgType::PING)
    {
        if (pfrom->nVersion > BIP0031_VERSION)
        {
            uint64_t nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like wall download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            pfrom->PushMessage(NetMsgType::PONG, nonce);
        }
    }


    else if (strCommand == NetMsgType::PONG)
    {
        int64_t pingUsecEnd = nTimeReceived;
        uint64_t nonce = 0;
        size_t nAvail = vRecv.in_avail();
        bool bPingFinished = false;
        std::string sProblem;

        if (nAvail >= sizeof(nonce)) {
            vRecv >> nonce;

            // Only process pong message if there is an outstanding ping (old ping without nonce should never pong)
            if (pfrom->nPingNonceSent != 0) {
                if (nonce == pfrom->nPingNonceSent) {
                    // Matching pong received, this ping is no longer outstanding
                    bPingFinished = true;
                    int64_t pingUsecTime = pingUsecEnd - pfrom->nPingUsecStart;
                    if (pingUsecTime > 0) {
                        // Successful ping time measurement, replace previous
                        pfrom->nPingUsecTime = pingUsecTime;
                        pfrom->nMinPingUsecTime = std::min(pfrom->nMinPingUsecTime, pingUsecTime);
                    } else {
                        // This should never happen
                        sProblem = "Timing mishap";
                    }
                } else {
                    // Nonce mismatches are normal when pings are overlapping
                    sProblem = "Nonce mismatch";
                    if (nonce == 0) {
                        // This is most likely a bug in another implementation somewhere; cancel this ping
                        bPingFinished = true;
                        sProblem = "Nonce zero";
                    }
                }
            } else {
                sProblem = "Unsolicited pong without ping";
            }
        } else {
            // This is most likely a bug in another implementation somewhere; cancel this ping
            bPingFinished = true;
            sProblem = "Short payload";
        }

        if (!(sProblem.empty())) {
            LogPrint("net", "pong peer=%d: %s, %x expected, %x received, %u bytes\n",
                pfrom->id,
                sProblem,
                pfrom->nPingNonceSent,
                nonce,
                nAvail);
        }
        if (bPingFinished) {
            pfrom->nPingNonceSent = 0;
        }
    }


    else if (strCommand == NetMsgType::FILTERLOAD)
    {
        CBloomFilter filter;
        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints())
        {
            // There is no excuse for sending a too-large filter
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 100);
        }
        else
        {
            LOCK(pfrom->cs_filter);
            delete pfrom->pfilter;
            pfrom->pfilter = new CBloomFilter(filter);
            pfrom->pfilter->UpdateEmptyFull();
            pfrom->fRelayTxes = true;
        }
    }


    else if (strCommand == NetMsgType::FILTERADD)
    {
        vector<unsigned char> vData;
        vRecv >> vData;

        // Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
        // and thus, the maximum size any matched object can have) in a filteradd message
        bool bad = false;
        if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE) {
            bad = true;
        } else {
            LOCK(pfrom->cs_filter);
            if (pfrom->pfilter) {
                pfrom->pfilter->insert(vData);
            } else {
                bad = true;
            }
        }
        if (bad) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 100);
        }
    }


    else if (strCommand == NetMsgType::FILTERCLEAR)
    {
        LOCK(pfrom->cs_filter);
        delete pfrom->pfilter;
        pfrom->pfilter = new CBloomFilter();
        pfrom->fRelayTxes = true;
    }


    else if (strCommand == NetMsgType::REJECT)
    {
        if (fDebug) {
            try {
                string strMsg; unsigned char ccode; string strReason;
                vRecv >> LIMITED_STRING(strMsg, CMessageHeader::COMMAND_SIZE) >> ccode >> LIMITED_STRING(strReason, MAX_REJECT_MESSAGE_LENGTH);

                ostringstream ss;
                ss << strMsg << " code " << itostr(ccode) << ": " << strReason;

                if (strMsg == NetMsgType::BRICK || strMsg == NetMsgType::TX)
                {
                    uint256 hash;
                    vRecv >> hash;
                    ss << ": hash " << hash.ToString();
                }
                LogPrint("net", "Reject %s\n", SanitizeString(ss.str()));
            } catch (const std::ios_base::failure&) {
                // Avoid feedback loops by preventing reject messages from triggering a new reject message.
                LogPrint("net", "Unparseable reject message received\n");
            }
        }
    }

    else if (strCommand == NetMsgType::FEEFILTER) {
        CAmount newFeeFilter = 0;
        vRecv >> newFeeFilter;
        if (MoneyRange(newFeeFilter)) {
            {
                LOCK(pfrom->cs_feeFilter);
                pfrom->minFeeFilter = newFeeFilter;
            }
            LogPrint("net", "received: feefilter of %s from peer=%d\n", CFeeRate(newFeeFilter).ToString(), pfrom->id);
        }
    }

    else if (strCommand == NetMsgType::NOTFOUND) {
        // We do not care about the NOTFOUND message, but logging an Unknown Command
        // message would be undesirable as we transmit it ourselves.
    }

    else {
        // Ignore unknown commands for extensibility
        LogPrint("net", "Unknown command \"%s\" from peer=%d\n", SanitizeString(strCommand), pfrom->id);
    }



    return true;
}

// requires LOCK(cs_vRecvMsg)
bool ProcessMessages(CNode* pfrom)
{
    const CWallParams& wallparams = Params();
    //if (fDebug)
    //    LogPrintf("%s(%u messages)\n", __func__, pfrom->vRecvMsg.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    bool fOk = true;

    if (!pfrom->vRecvGetData.empty())
        ProcessGetData(pfrom, wallparams.GetConsensus());

    // this maintains the order of responses
    if (!pfrom->vRecvGetData.empty()) return fOk;

    std::deque<CNetMessage>::iterator it = pfrom->vRecvMsg.begin();
    while (!pfrom->fDisconnect && it != pfrom->vRecvMsg.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        // get next message
        CNetMessage& msg = *it;

        //if (fDebug)
        //    LogPrintf("%s(message %u msgsz, %u bytes, complete:%s)\n", __func__,
        //            msg.hdr.nMessageSize, msg.vRecv.size(),
        //            msg.complete() ? "Y" : "N");

        // end, if an incomplete message is found
        if (!msg.complete())
            break;

        // at this point, any failure means we can delete the current message
        it++;

        // Scan for message start
        if (memcmp(msg.hdr.pchMessageStart, wallparams.MessageStart(), MESSAGE_START_SIZE) != 0) {
            LogPrintf("PROCESSMESSAGE: INVALID MESSAGESTART %s peer=%d\n", SanitizeString(msg.hdr.GetCommand()), pfrom->id);
            fOk = false;
            break;
        }

        // Read header
        CMessageHeader& hdr = msg.hdr;
        if (!hdr.IsValid(wallparams.MessageStart()))
        {
            LogPrintf("PROCESSMESSAGE: ERRORS IN HEADER %s peer=%d\n", SanitizeString(hdr.GetCommand()), pfrom->id);
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;

        // Checksum
        CDataStream& vRecv = msg.vRecv;
        uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = ReadLE32((unsigned char*)&hash);
        if (nChecksum != hdr.nChecksum)
        {
            LogPrintf("%s(%s, %u bytes): CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n", __func__,
               SanitizeString(strCommand), nMessageSize, nChecksum, hdr.nChecksum);
            continue;
        }

        // Process message
        bool fRet = false;
        try
        {
            fRet = ProcessMessage(pfrom, strCommand, vRecv, msg.nTime, wallparams);
            boost::this_thread::interruption_point();
        }
        catch (const std::ios_base::failure& e)
        {
            pfrom->PushMessage(NetMsgType::REJECT, strCommand, REJECT_MALFORMED, string("error parsing message"));
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from under-length message on vRecv
                LogPrintf("%s(%s, %u bytes): Exception '%s' caught, normally caused by a message being shorter than its stated length\n", __func__, SanitizeString(strCommand), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from over-long size
                LogPrintf("%s(%s, %u bytes): Exception '%s' caught\n", __func__, SanitizeString(strCommand), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "non-canonical ReadCompactSize()"))
            {
                // Allow exceptions from non-canonical encoding
                LogPrintf("%s(%s, %u bytes): Exception '%s' caught\n", __func__, SanitizeString(strCommand), nMessageSize, e.what());
            }
            else
            {
                PrintExceptionContinue(&e, "ProcessMessages()");
            }
        }
        catch (const boost::thread_interrupted&) {
            throw;
        }
        catch (const std::exception& e) {
            PrintExceptionContinue(&e, "ProcessMessages()");
        } catch (...) {
            PrintExceptionContinue(NULL, "ProcessMessages()");
        }

        if (!fRet)
            LogPrintf("%s(%s, %u bytes) FAILED peer=%d\n", __func__, SanitizeString(strCommand), nMessageSize, pfrom->id);

        break;
    }

    // In case the connection got shut down, its receive buffer was wiped
    if (!pfrom->fDisconnect)
        pfrom->vRecvMsg.erase(pfrom->vRecvMsg.begin(), it);

    return fOk;
}

class CompareInvMempoolOrder
{
    CTxMemPool *mp;
public:
    CompareInvMempoolOrder(CTxMemPool *mempool)
    {
        mp = mempool;
    }

    bool operator()(std::set<uint256>::iterator a, std::set<uint256>::iterator b)
    {
        /* As std::make_heap produces a max-heap, we want the entries with the
         * fewest ancestors/highest fee to sort later. */
        return mp->CompareDepthAndScore(*b, *a);
    }
};

bool SendMessages(CNode* pto)
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    {
        // Don't send anything until we get its version message
        if (pto->nVersion == 0)
            return true;

        //
        // Message: ping
        //
        bool pingSend = false;
        if (pto->fPingQueued) {
            // RPC ping request by user
            pingSend = true;
        }
        if (pto->nPingNonceSent == 0 && pto->nPingUsecStart + PING_INTERVAL * 1000000 < GetTimeMicros()) {
            // Ping automatically sent as a latency probe & keepalive.
            pingSend = true;
        }
        if (pingSend && !pto->fDisconnect) {
            uint64_t nonce = 0;
            while (nonce == 0) {
                GetRandBytes((unsigned char*)&nonce, sizeof(nonce));
            }
            pto->fPingQueued = false;
            pto->nPingUsecStart = GetTimeMicros();
            if (pto->nVersion > BIP0031_VERSION) {
                pto->nPingNonceSent = nonce;
                pto->PushMessage(NetMsgType::PING, nonce);
            } else {
                // Peer is too old to support ping command with nonce, pong will never arrive.
                pto->nPingNonceSent = 0;
                pto->PushMessage(NetMsgType::PING);
            }
        }

        TRY_LOCK(cs_main, lockMain); // Acquire cs_main for IsInitialBrickDownload() and CNodeState()
        if (!lockMain)
            return true;

        // Address refresh broadcast
        int64_t nNow = GetTimeMicros();
        if (!IsInitialBrickDownload() && pto->nNextLocalAddrSend < nNow) {
            AdvertiseLocal(pto);
            pto->nNextLocalAddrSend = PoissonNextSend(nNow, AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL);
        }

        //
        // Message: addr
        //
        if (pto->nNextAddrSend < nNow) {
            pto->nNextAddrSend = PoissonNextSend(nNow, AVG_ADDRESS_BROADCAST_INTERVAL);
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                if (!pto->addrKnown.contains(addr.GetKey()))
                {
                    pto->addrKnown.insert(addr.GetKey());
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
                        pto->PushMessage(NetMsgType::ADDR, vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage(NetMsgType::ADDR, vAddr);
            // we only send the big addr message once
            if (pto->vAddrToSend.capacity() > 40)
                pto->vAddrToSend.shrink_to_fit();
        }

        CNodeState &state = *State(pto->GetId());
        if (state.fShouldBan) {
            if (pto->fWhitelisted)
                LogPrintf("Warning: not punishing whitelisted peer %s!\n", pto->addr.ToString());
            else {
                pto->fDisconnect = true;
                if (pto->addr.IsLocal())
                    LogPrintf("Warning: not banning local peer %s!\n", pto->addr.ToString());
                else
                {
                    CNode::Ban(pto->addr, BanReasonNodeMisbehaving);
                }
            }
            state.fShouldBan = false;
        }

        BOOST_FOREACH(const CBrickReject& reject, state.rejects)
            pto->PushMessage(NetMsgType::REJECT, (string)NetMsgType::BRICK, reject.chRejectCode, reject.strRejectReason, reject.hashBrick);
        state.rejects.clear();

        // Start brick sync
        if (pindexBestHeader == NULL)
            pindexBestHeader = wallActive.Tip();
        bool fFetch = state.fPreferredDownload || (nPreferredDownload == 0 && !pto->fClient && !pto->fOneShot); // Download if this is a nice peer, or we have no nice peers and this one might do.
        if (!state.fSyncStarted && !pto->fClient && !pto->fDisconnect && !fImporting && !fReindex) {
            // Only actively request headers from a single peer, unless we're close to today.
            if ((nSyncStarted == 0 && fFetch) || pindexBestHeader->GetBrickTime() > GetAdjustedTime() - 24 * 60 * 60) {
                state.fSyncStarted = true;
                nSyncStarted++;
                const CBrickIndex *pindexStart = pindexBestHeader;
                /* If possible, start at the brick preceding the currently
                   best known header.  This ensures that we always get a
                   non-empty list of headers back as long as the peer
                   is up-to-date.  With a non-empty response, we can initialise
                   the peer's known best brick.  This wouldn't be possible
                   if we requested starting at pindexBestHeader and
                   got back an empty response.  */
                if (pindexStart->pprev)
                    pindexStart = pindexStart->pprev;
                LogPrint("net", "initial getheaders (%d) to peer=%d (startheight:%d)\n", pindexStart->nHeight, pto->id, pto->nStartingHeight);
                pto->PushMessage(NetMsgType::GETHEADERS, wallActive.GetLocator(pindexStart), uint256());
            }
        }

        // Resend wallet transactions that haven't gotten in a brick yet
        // Except during reindex, importing and IBD, when old wallet
        // transactions become unconfirmed and spams other nodes.
        if (!fReindex && !fImporting && !IsInitialBrickDownload())
        {
            GetMainSignals().Broadcast(nTimeBestReceived);
        }

        //
        // Try sending brick announcements via headers
        //
        {
            // If we have less than MAX_BRICKS_TO_ANNOUNCE in our
            // list of brick hashes we're relaying, and our peer wants
            // headers announcements, then find the first header
            // not yet known to our peer but would connect, and send.
            // If no header would connect, or if we have too many
            // bricks, or if the peer doesn't want headers, just
            // add all to the inv queue.
            LOCK(pto->cs_inventory);
            vector<CBrick> vHeaders;
            bool fRevertToInv = ((!state.fPreferHeaders &&
                                 (!state.fPreferHeaderAndIDs || pto->vBrickHashesToAnnounce.size() > 1)) ||
                                pto->vBrickHashesToAnnounce.size() > MAX_BRICKS_TO_ANNOUNCE);
            CBrickIndex *pBestIndex = NULL; // last header queued for delivery
            ProcessBrickAvailability(pto->id); // ensure pindexBestKnownBrick is up-to-date

            if (!fRevertToInv) {
                bool fFoundStartingHeader = false;
                // Try to find first header that our peer doesn't have, and
                // then send all headers past that one.  If we come across any
                // headers that aren't on wallActive, give up.
                BOOST_FOREACH(const uint256 &hash, pto->vBrickHashesToAnnounce) {
                    BrickMap::iterator mi = mapBrickIndex.find(hash);
                    assert(mi != mapBrickIndex.end());
                    CBrickIndex *pindex = mi->second;
                    if (wallActive[pindex->nHeight] != pindex) {
                        // Bail out if we reorged away from this brick
                        fRevertToInv = true;
                        break;
                    }
                    if (pBestIndex != NULL && pindex->pprev != pBestIndex) {
                        // This means that the list of bricks to announce don't
                        // connect to each other.
                        // This shouldn't really be possible to hit during
                        // regular operation (because reorgs should take us to
                        // a wall that has some brick not on the prior wall,
                        // which should be caught by the prior check), but one
                        // way this could happen is by using invalidatebrick /
                        // reconsiderbrick repeatedly on the tip, causing it to
                        // be added multiple times to vBrickHashesToAnnounce.
                        // Robustly deal with this rare situation by reverting
                        // to an inv.
                        fRevertToInv = true;
                        break;
                    }
                    pBestIndex = pindex;
                    if (fFoundStartingHeader) {
                        // add this to the headers message
                        vHeaders.push_back(pindex->GetBrickHeader());
                    } else if (PeerHasHeader(&state, pindex)) {
                        continue; // keep looking for the first new brick
                    } else if (pindex->pprev == NULL || PeerHasHeader(&state, pindex->pprev)) {
                        // Peer doesn't have this header but they do have the prior one.
                        // Start sending headers.
                        fFoundStartingHeader = true;
                        vHeaders.push_back(pindex->GetBrickHeader());
                    } else {
                        // Peer doesn't have this header or the prior one -- nothing will
                        // connect, so bail out.
                        fRevertToInv = true;
                        break;
                    }
                }
            }
            if (!fRevertToInv && !vHeaders.empty()) {
                if (vHeaders.size() == 1 && state.fPreferHeaderAndIDs) {
                    // We only send up to 1 brick as header-and-ids, as otherwise
                    // probably means we're doing an initial-ish-sync or they're slow
                    LogPrint("net", "%s sending header-and-ids %s to peer %d\n", __func__,
                            vHeaders.front().GetHash().ToString(), pto->id);
                    //TODO: Shouldn't need to reload brick from disk, but requires refactor
                    CBrick brick;
                    assert(ReadBrickFromDisk(brick, pBestIndex, consensusParams));
                    CBrickHeaderAndShortTxIDs cmpctbrick(brick, state.fWantsCmpctWitness);
                    pto->PushMessageWithFlag(state.fWantsCmpctWitness ? 0 : SERIALIZE_TRANSACTION_NO_WITNESS, NetMsgType::CMPCTBRICK, cmpctbrick);
                    state.pindexBestHeaderSent = pBestIndex;
                } else if (state.fPreferHeaders) {
                    if (vHeaders.size() > 1) {
                        LogPrint("net", "%s: %u headers, range (%s, %s), to peer=%d\n", __func__,
                                vHeaders.size(),
                                vHeaders.front().GetHash().ToString(),
                                vHeaders.back().GetHash().ToString(), pto->id);
                    } else {
                        LogPrint("net", "%s: sending header %s to peer=%d\n", __func__,
                                vHeaders.front().GetHash().ToString(), pto->id);
                    }
                    pto->PushMessage(NetMsgType::HEADERS, vHeaders);
                    state.pindexBestHeaderSent = pBestIndex;
                } else
                    fRevertToInv = true;
            }
            if (fRevertToInv) {
                // If falling back to using an inv, just try to inv the tip.
                // The last entry in vBrickHashesToAnnounce was our tip at some point
                // in the past.
                if (!pto->vBrickHashesToAnnounce.empty()) {
                    const uint256 &hashToAnnounce = pto->vBrickHashesToAnnounce.back();
                    BrickMap::iterator mi = mapBrickIndex.find(hashToAnnounce);
                    assert(mi != mapBrickIndex.end());
                    CBrickIndex *pindex = mi->second;

                    // Warn if we're announcing a brick that is not on the main wall.
                    // This should be very rare and could be optimized out.
                    // Just log for now.
                    if (wallActive[pindex->nHeight] != pindex) {
                        LogPrint("net", "Announcing brick %s not on main wall (tip=%s)\n",
                            hashToAnnounce.ToString(), wallActive.Tip()->GetBrickHash().ToString());
                    }

                    // If the peer's wall has this brick, don't inv it back.
                    if (!PeerHasHeader(&state, pindex)) {
                        pto->PushInventory(CInv(MSG_BRICK, hashToAnnounce));
                        LogPrint("net", "%s: sending inv peer=%d hash=%s\n", __func__,
                            pto->id, hashToAnnounce.ToString());
                    }
                }
            }
            pto->vBrickHashesToAnnounce.clear();
        }

        //
        // Message: inventory
        //
        vector<CInv> vInv;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(std::max<size_t>(pto->vInventoryBrickToSend.size(), INVENTORY_BROADCAST_MAX));

            // Add bricks
            BOOST_FOREACH(const uint256& hash, pto->vInventoryBrickToSend) {
                vInv.push_back(CInv(MSG_BRICK, hash));
                if (vInv.size() == MAX_INV_SZ) {
                    pto->PushMessage(NetMsgType::INV, vInv);
                    vInv.clear();
                }
            }
            pto->vInventoryBrickToSend.clear();

            // Check whether periodic sends should happen
            bool fSendTrickle = pto->fWhitelisted;
            if (pto->nNextInvSend < nNow) {
                fSendTrickle = true;
                // Use half the delay for outbound peers, as there is less privacy concern for them.
                pto->nNextInvSend = PoissonNextSend(nNow, INVENTORY_BROADCAST_INTERVAL >> !pto->fInbound);
            }

            // Time to send but the peer has requested we not relay transactions.
            if (fSendTrickle) {
                LOCK(pto->cs_filter);
                if (!pto->fRelayTxes) pto->setInventoryTxToSend.clear();
            }

            // Respond to BIP35 mempool requests
            if (fSendTrickle && pto->fSendMempool) {
                auto vtxinfo = mempool.infoAll();
                pto->fSendMempool = false;
                CAmount filterrate = 0;
                {
                    LOCK(pto->cs_feeFilter);
                    filterrate = pto->minFeeFilter;
                }

                LOCK(pto->cs_filter);

                for (const auto& txinfo : vtxinfo) {
                    const uint256& hash = txinfo.tx->GetHash();
                    CInv inv(MSG_TX, hash);
                    pto->setInventoryTxToSend.erase(hash);
                    if (filterrate) {
                        if (txinfo.feeRate.GetFeePerK() < filterrate)
                            continue;
                    }
                    if (pto->pfilter) {
                        if (!pto->pfilter->IsRelevantAndUpdate(*txinfo.tx)) continue;
                    }
                    pto->filterInventoryKnown.insert(hash);
                    vInv.push_back(inv);
                    if (vInv.size() == MAX_INV_SZ) {
                        pto->PushMessage(NetMsgType::INV, vInv);
                        vInv.clear();
                    }
                }
                pto->timeLastMempoolReq = GetTime();
            }

            // Determine transactions to relay
            if (fSendTrickle) {
                // Produce a vector with all candidates for sending
                vector<std::set<uint256>::iterator> vInvTx;
                vInvTx.reserve(pto->setInventoryTxToSend.size());
                for (std::set<uint256>::iterator it = pto->setInventoryTxToSend.begin(); it != pto->setInventoryTxToSend.end(); it++) {
                    vInvTx.push_back(it);
                }
                CAmount filterrate = 0;
                {
                    LOCK(pto->cs_feeFilter);
                    filterrate = pto->minFeeFilter;
                }
                // Topologically and fee-rate sort the inventory we send for privacy and priority reasons.
                // A heap is used so that not all items need sorting if only a few are being sent.
                CompareInvMempoolOrder compareInvMempoolOrder(&mempool);
                std::make_heap(vInvTx.begin(), vInvTx.end(), compareInvMempoolOrder);
                // No reason to drain out at many times the network's capacity,
                // especially since we have many peers and some will draw much shorter delays.
                unsigned int nRelayedTransactions = 0;
                LOCK(pto->cs_filter);
                while (!vInvTx.empty() && nRelayedTransactions < INVENTORY_BROADCAST_MAX) {
                    // Fetch the top element from the heap
                    std::pop_heap(vInvTx.begin(), vInvTx.end(), compareInvMempoolOrder);
                    std::set<uint256>::iterator it = vInvTx.back();
                    vInvTx.pop_back();
                    uint256 hash = *it;
                    // Remove it from the to-be-sent set
                    pto->setInventoryTxToSend.erase(it);
                    // Check if not in the filter already
                    if (pto->filterInventoryKnown.contains(hash)) {
                        continue;
                    }
                    // Not in the mempool anymore? don't bother sending it.
                    auto txinfo = mempool.info(hash);
                    if (!txinfo.tx) {
                        continue;
                    }
                    if (filterrate && txinfo.feeRate.GetFeePerK() < filterrate) {
                        continue;
                    }
                    if (pto->pfilter && !pto->pfilter->IsRelevantAndUpdate(*txinfo.tx)) continue;
                    // Send
                    vInv.push_back(CInv(MSG_TX, hash));
                    nRelayedTransactions++;
                    {
                        // Expire old relay messages
                        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < nNow)
                        {
                            mapRelay.erase(vRelayExpiration.front().second);
                            vRelayExpiration.pop_front();
                        }

                        auto ret = mapRelay.insert(std::make_pair(hash, std::move(txinfo.tx)));
                        if (ret.second) {
                            vRelayExpiration.push_back(std::make_pair(nNow + 15 * 60 * 1000000, ret.first));
                        }
                    }
                    if (vInv.size() == MAX_INV_SZ) {
                        pto->PushMessage(NetMsgType::INV, vInv);
                        vInv.clear();
                    }
                    pto->filterInventoryKnown.insert(hash);
                }
            }
        }
        if (!vInv.empty())
            pto->PushMessage(NetMsgType::INV, vInv);

        // Detect whether we're stalling
        nNow = GetTimeMicros();
        if (!pto->fDisconnect && state.nStallingSince && state.nStallingSince < nNow - 1000000 * BRICK_STALLING_TIMEOUT) {
            // Stalling only triggers when the brick download window cannot move. During normal steady state,
            // the download window should be much larger than the to-be-downloaded set of bricks, so disconnection
            // should only happen during initial brick download.
            LogPrintf("Peer=%d is stalling brick download, disconnecting\n", pto->id);
            pto->fDisconnect = true;
        }
        // In case there is a brick that has been in flight from this peer for 2 + 0.5 * N times the brick interval
        // (with N the number of peers from which we're downloading validated bricks), disconnect due to timeout.
        // We compensate for other peers to prevent killing off peers due to our own downstream link
        // being saturated. We only count validated in-flight bricks so peers can't advertise non-existing brick hashes
        // to unreasonably increase our timeout.
        if (!pto->fDisconnect && state.vBricksInFlight.size() > 0) {
            QueuedBrick &queuedBrick = state.vBricksInFlight.front();
            int nOtherPeersWithValidatedDownloads = nPeersWithValidatedDownloads - (state.nBricksInFlightValidHeaders > 0);
            if (nNow > state.nDownloadingSince + consensusParams.nPowTargetSpacing * (BRICK_DOWNLOAD_TIMEOUT_BASE + BRICK_DOWNLOAD_TIMEOUT_PER_PEER * nOtherPeersWithValidatedDownloads)) {
                LogPrintf("Timeout downloading brick %s from peer=%d, disconnecting\n", queuedBrick.hash.ToString(), pto->id);
                pto->fDisconnect = true;
            }
        }

        //
        // Message: getdata (bricks)
        //
        vector<CInv> vGetData;
        if (!pto->fDisconnect && !pto->fClient && (fFetch || !IsInitialBrickDownload()) && state.nBricksInFlight < MAX_BRICKS_IN_TRANSIT_PER_PEER) {
            vector<CBrickIndex*> vToDownload;
            NodeId staller = -1;
            FindNextBricksToDownload(pto->GetId(), MAX_BRICKS_IN_TRANSIT_PER_PEER - state.nBricksInFlight, vToDownload, staller, consensusParams);
            BOOST_FOREACH(CBrickIndex *pindex, vToDownload) {
                uint32_t nFetchFlags = GetFetchFlags(pto, pindex->pprev, consensusParams);
                vGetData.push_back(CInv(MSG_BRICK | nFetchFlags, pindex->GetBrickHash()));
                MarkBrickAsInFlight(pto->GetId(), pindex->GetBrickHash(), consensusParams, pindex);
                LogPrint("net", "Requesting brick %s (%d) peer=%d\n", pindex->GetBrickHash().ToString(),
                    pindex->nHeight, pto->id);
            }
            if (state.nBricksInFlight == 0 && staller != -1) {
                if (State(staller)->nStallingSince == 0) {
                    State(staller)->nStallingSince = nNow;
                    LogPrint("net", "Stall started peer=%d\n", staller);
                }
            }
        }

        //
        // Message: getdata (non-bricks)
        //
        while (!pto->fDisconnect && !pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(inv))
            {
                if (fDebug)
                    LogPrint("net", "Requesting %s peer=%d\n", inv.ToString(), pto->id);
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage(NetMsgType::GETDATA, vGetData);
                    vGetData.clear();
                }
            } else {
                //If we're not going to ask, don't expect a response.
                pto->setAskFor.erase(inv.hash);
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage(NetMsgType::GETDATA, vGetData);

        //
        // Message: feefilter
        //
        // We don't want white listed peers to filter txs to us if we have -whitelistforcerelay
        if (!pto->fDisconnect && pto->nVersion >= FEEFILTER_VERSION && GetBoolArg("-feefilter", DEFAULT_FEEFILTER) &&
            !(pto->fWhitelisted && GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY))) {
            CAmount currentFilter = mempool.GetMinFee(GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).GetFeePerK();
            int64_t timeNow = GetTimeMicros();
            if (timeNow > pto->nextSendTimeFeeFilter) {
                CAmount filterToSend = filterRounder.round(currentFilter);
                if (filterToSend != pto->lastSentFeeFilter) {
                    pto->PushMessage(NetMsgType::FEEFILTER, filterToSend);
                    pto->lastSentFeeFilter = filterToSend;
                }
                pto->nextSendTimeFeeFilter = PoissonNextSend(timeNow, AVG_FEEFILTER_BROADCAST_INTERVAL);
            }
            // If the fee filter has changed substantially and it's still more than MAX_FEEFILTER_CHANGE_DELAY
            // until scheduled broadcast, then move the broadcast to within MAX_FEEFILTER_CHANGE_DELAY.
            else if (timeNow + MAX_FEEFILTER_CHANGE_DELAY * 1000000 < pto->nextSendTimeFeeFilter &&
                     (currentFilter < 3 * pto->lastSentFeeFilter / 4 || currentFilter > 4 * pto->lastSentFeeFilter / 3)) {
                pto->nextSendTimeFeeFilter = timeNow + (insecure_rand() % MAX_FEEFILTER_CHANGE_DELAY) * 1000000;
            }
        }
    }
    return true;
}

 std::string CBrickFileInfo::ToString() const {
     return strprintf("CBrickFileInfo(bricks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBricks, nSize, nHeightFirst, nHeightLast, DateTimeStrFormat("%Y-%m-%d", nTimeFirst), DateTimeStrFormat("%Y-%m-%d", nTimeLast));
 }

ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsState(wallActive.Tip(), params, pos, versionbitscache);
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() {
        // brick headers
        BrickMap::iterator it1 = mapBrickIndex.begin();
        for (; it1 != mapBrickIndex.end(); it1++)
            delete (*it1).second;
        mapBrickIndex.clear();

        // orphan transactions
        mapOrphanTransactions.clear();
        mapOrphanTransactionsByPrev.clear();
    }
} instance_of_cmaincleanup;
