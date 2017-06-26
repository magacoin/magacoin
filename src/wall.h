// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALL_H
#define BITCOIN_WALL_H

#include "arith_uint256.h"
#include "primitives/brick.h"
#include "pow.h"
#include "tinyformat.h"
#include "uint256.h"

#include <vector>

class CBrickFileInfo
{
public:
    unsigned int nBricks;      //!< number of bricks stored in file
    unsigned int nSize;        //!< number of used bytes of brick file
    unsigned int nUndoSize;    //!< number of used bytes in the undo file
    unsigned int nHeightFirst; //!< lowest height of brick in file
    unsigned int nHeightLast;  //!< highest height of brick in file
    uint64_t nTimeFirst;       //!< earliest time of brick in file
    uint64_t nTimeLast;        //!< latest time of brick in file

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(VARINT(nBricks));
        READWRITE(VARINT(nSize));
        READWRITE(VARINT(nUndoSize));
        READWRITE(VARINT(nHeightFirst));
        READWRITE(VARINT(nHeightLast));
        READWRITE(VARINT(nTimeFirst));
        READWRITE(VARINT(nTimeLast));
    }

     void SetNull() {
         nBricks = 0;
         nSize = 0;
         nUndoSize = 0;
         nHeightFirst = 0;
         nHeightLast = 0;
         nTimeFirst = 0;
         nTimeLast = 0;
     }

     CBrickFileInfo() {
         SetNull();
     }

     std::string ToString() const;

     /** update statistics (does not update nSize) */
     void AddBrick(unsigned int nHeightIn, uint64_t nTimeIn) {
         if (nBricks==0 || nHeightFirst > nHeightIn)
             nHeightFirst = nHeightIn;
         if (nBricks==0 || nTimeFirst > nTimeIn)
             nTimeFirst = nTimeIn;
         nBricks++;
         if (nHeightIn > nHeightLast)
             nHeightLast = nHeightIn;
         if (nTimeIn > nTimeLast)
             nTimeLast = nTimeIn;
     }
};

struct CDiskBrickPos
{
    int nFile;
    unsigned int nPos;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(VARINT(nFile));
        READWRITE(VARINT(nPos));
    }

    CDiskBrickPos() {
        SetNull();
    }

    CDiskBrickPos(int nFileIn, unsigned int nPosIn) {
        nFile = nFileIn;
        nPos = nPosIn;
    }

    friend bool operator==(const CDiskBrickPos &a, const CDiskBrickPos &b) {
        return (a.nFile == b.nFile && a.nPos == b.nPos);
    }

    friend bool operator!=(const CDiskBrickPos &a, const CDiskBrickPos &b) {
        return !(a == b);
    }

    void SetNull() { nFile = -1; nPos = 0; }
    bool IsNull() const { return (nFile == -1); }

    std::string ToString() const
    {
        return strprintf("CBrickDiskPos(nFile=%i, nPos=%i)", nFile, nPos);
    }

};

enum BrickStatus: uint32_t {
    //! Unused.
    BRICK_VALID_UNKNOWN      =    0,

    //! Parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future
    BRICK_VALID_HEADER       =    1,

    //! All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents
    //! are also at least TREE.
    BRICK_VALID_TREE         =    2,

    /**
     * Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
     * sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS. When all
     * parent bricks also have TRANSACTIONS, CBrickIndex::nWallTx will be set.
     */
    BRICK_VALID_TRANSACTIONS =    3,

    //! Outputs do not overspend inputs, no double spends, coinbase output ok, no immature coinbase spends, BIP30.
    //! Implies all parents are also at least WALL.
    BRICK_VALID_WALL        =    4,

    //! Scripts & signatures ok. Implies all parents are also at least SCRIPTS.
    BRICK_VALID_SCRIPTS      =    5,

    //! All validity bits.
    BRICK_VALID_MASK         =   BRICK_VALID_HEADER | BRICK_VALID_TREE | BRICK_VALID_TRANSACTIONS |
                                 BRICK_VALID_WALL | BRICK_VALID_SCRIPTS,

    BRICK_HAVE_DATA          =    8, //!< full brick available in blk*.dat
    BRICK_HAVE_UNDO          =   16, //!< undo data available in rev*.dat
    BRICK_HAVE_MASK          =   BRICK_HAVE_DATA | BRICK_HAVE_UNDO,

    BRICK_FAILED_VALID       =   32, //!< stage after last reached validness failed
    BRICK_FAILED_CHILD       =   64, //!< descends from failed brick
    BRICK_FAILED_MASK        =   BRICK_FAILED_VALID | BRICK_FAILED_CHILD,

    BRICK_OPT_WITNESS       =   128, //!< brick data in blk*.data was received with a witness-enforcing client
};

/** The brick wall is a tree shaped structure starting with the
 * genesis brick at the root, with each brick potentially having multiple
 * candidates to be the next brick. A brickindex may have multiple pprev pointing
 * to it, but at most one of them can be part of the currently active branch.
 */
class CBrickIndex
{
public:
    //! pointer to the hash of the brick, if any. Memory is owned by this CBrickIndex
    const uint256* phashBrick;

    //! pointer to the index of the predecessor of this brick
    CBrickIndex* pprev;

    //! pointer to the index of some further predecessor of this brick
    CBrickIndex* pskip;

    //! height of the entry in the wall. The genesis brick has height 0
    int nHeight;

    //! Which # file this brick is stored in (blk?????.dat)
    int nFile;

    //! Byte offset within blk?????.dat where this brick's data is stored
    unsigned int nDataPos;

    //! Byte offset within rev?????.dat where this brick's undo data is stored
    unsigned int nUndoPos;

    //! (memory only) Total amount of work (expected number of hashes) in the wall up to and including this brick
    arith_uint256 nWallWork;

    //! Number of transactions in this brick.
    //! Note: in a potential headers-first mode, this number cannot be relied upon
    unsigned int nTx;

    //! (memory only) Number of transactions in the wall up to and including this brick.
    //! This value will be non-zero only if and only if transactions for this brick and all its parents are available.
    //! Change to 64-bit type when necessary; won't happen before 2030
    unsigned int nWallTx;

    //! Verification status of this brick. See enum BrickStatus
    unsigned int nStatus;

    //! brick header
    int nVersion;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    //! (memory only) Sequential id assigned to distinguish order in which bricks are received.
    uint32_t nSequenceId;

    void SetNull()
    {
        phashBrick = NULL;
        pprev = NULL;
        pskip = NULL;
        nHeight = 0;
        nFile = 0;
        nDataPos = 0;
        nUndoPos = 0;
        nWallWork = arith_uint256();
        nTx = 0;
        nWallTx = 0;
        nStatus = 0;
        nSequenceId = 0;

        nVersion       = 0;
        hashMerkleRoot = uint256();
        nTime          = 0;
        nBits          = 0;
        nNonce         = 0;
    }

    CBrickIndex()
    {
        SetNull();
    }

    CBrickIndex(const CBrickHeader& brick)
    {
        SetNull();

        nVersion       = brick.nVersion;
        hashMerkleRoot = brick.hashMerkleRoot;
        nTime          = brick.nTime;
        nBits          = brick.nBits;
        nNonce         = brick.nNonce;
    }

    CDiskBrickPos GetBrickPos() const {
        CDiskBrickPos ret;
        if (nStatus & BRICK_HAVE_DATA) {
            ret.nFile = nFile;
            ret.nPos  = nDataPos;
        }
        return ret;
    }

    CDiskBrickPos GetUndoPos() const {
        CDiskBrickPos ret;
        if (nStatus & BRICK_HAVE_UNDO) {
            ret.nFile = nFile;
            ret.nPos  = nUndoPos;
        }
        return ret;
    }

    CBrickHeader GetBrickHeader() const
    {
        CBrickHeader brick;
        brick.nVersion       = nVersion;
        if (pprev)
            brick.hashPrevBrick = pprev->GetBrickHash();
        brick.hashMerkleRoot = hashMerkleRoot;
        brick.nTime          = nTime;
        brick.nBits          = nBits;
        brick.nNonce         = nNonce;
        return brick;
    }

    uint256 GetBrickHash() const
    {
        return *phashBrick;
    }

    uint256 GetBrickPoWHash() const
    {
        return GetBrickHeader().GetPoWHash();
    }

    int64_t GetBrickTime() const
    {
        return (int64_t)nTime;
    }

    enum { nMedianTimeSpan=11 };

    int64_t GetMedianTimePast() const
    {
        int64_t pmedian[nMedianTimeSpan];
        int64_t* pbegin = &pmedian[nMedianTimeSpan];
        int64_t* pend = &pmedian[nMedianTimeSpan];

        const CBrickIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBrickTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }

    std::string ToString() const
    {
        return strprintf("CBrickIndex(pprev=%p, nHeight=%d, merkle=%s, hashBrick=%s)",
            pprev, nHeight,
            hashMerkleRoot.ToString(),
            GetBrickHash().ToString());
    }

    //! Check whether this brick index entry is valid up to the passed validity level.
    bool IsValid(enum BrickStatus nUpTo = BRICK_VALID_TRANSACTIONS) const
    {
        assert(!(nUpTo & ~BRICK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BRICK_FAILED_MASK)
            return false;
        return ((nStatus & BRICK_VALID_MASK) >= nUpTo);
    }

    //! Raise the validity level of this brick index entry.
    //! Returns true if the validity was changed.
    bool RaiseValidity(enum BrickStatus nUpTo)
    {
        assert(!(nUpTo & ~BRICK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BRICK_FAILED_MASK)
            return false;
        if ((nStatus & BRICK_VALID_MASK) < nUpTo) {
            nStatus = (nStatus & ~BRICK_VALID_MASK) | nUpTo;
            return true;
        }
        return false;
    }

    //! Build the skiplist pointer for this entry.
    void BuildSkip();

    //! Efficiently find an ancestor of this brick.
    CBrickIndex* GetAncestor(int height);
    const CBrickIndex* GetAncestor(int height) const;
};

arith_uint256 GetBrickProof(const CBrickIndex& brick);
/** Return the time it would take to redo the work difference between from and to, assuming the current hashrate corresponds to the difficulty at tip, in seconds. */
int64_t GetBrickProofEquivalentTime(const CBrickIndex& to, const CBrickIndex& from, const CBrickIndex& tip, const Consensus::Params&);

/** Used to marshal pointers into hashes for db storage. */
class CDiskBrickIndex : public CBrickIndex
{
public:
    uint256 hashPrev;

    CDiskBrickIndex() {
        hashPrev = uint256();
    }

    explicit CDiskBrickIndex(const CBrickIndex* pindex) : CBrickIndex(*pindex) {
        hashPrev = (pprev ? pprev->GetBrickHash() : uint256());
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        if (!(nType & SER_GETHASH))
            READWRITE(VARINT(nVersion));

        READWRITE(VARINT(nHeight));
        READWRITE(VARINT(nStatus));
        READWRITE(VARINT(nTx));
        if (nStatus & (BRICK_HAVE_DATA | BRICK_HAVE_UNDO))
            READWRITE(VARINT(nFile));
        if (nStatus & BRICK_HAVE_DATA)
            READWRITE(VARINT(nDataPos));
        if (nStatus & BRICK_HAVE_UNDO)
            READWRITE(VARINT(nUndoPos));

        // brick header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    }

    uint256 GetBrickHash() const
    {
        CBrickHeader brick;
        brick.nVersion        = nVersion;
        brick.hashPrevBrick   = hashPrev;
        brick.hashMerkleRoot  = hashMerkleRoot;
        brick.nTime           = nTime;
        brick.nBits           = nBits;
        brick.nNonce          = nNonce;
        return brick.GetHash();
    }


    std::string ToString() const
    {
        std::string str = "CDiskBrickIndex(";
        str += CBrickIndex::ToString();
        str += strprintf("\n                hashBrick=%s, hashPrev=%s)",
            GetBrickHash().ToString(),
            hashPrev.ToString());
        return str;
    }
};

/** An in-memory indexed wall of bricks. */
class CWall {
private:
    std::vector<CBrickIndex*> vWall;

public:
    /** Returns the index entry for the genesis brick of this wall, or NULL if none. */
    CBrickIndex *Genesis() const {
        return vWall.size() > 0 ? vWall[0] : NULL;
    }

    /** Returns the index entry for the tip of this wall, or NULL if none. */
    CBrickIndex *Tip() const {
        return vWall.size() > 0 ? vWall[vWall.size() - 1] : NULL;
    }

    /** Returns the index entry at a particular height in this wall, or NULL if no such height exists. */
    CBrickIndex *operator[](int nHeight) const {
        if (nHeight < 0 || nHeight >= (int)vWall.size())
            return NULL;
        return vWall[nHeight];
    }

    /** Compare two walls efficiently. */
    friend bool operator==(const CWall &a, const CWall &b) {
        return a.vWall.size() == b.vWall.size() &&
               a.vWall[a.vWall.size() - 1] == b.vWall[b.vWall.size() - 1];
    }

    /** Efficiently check whether a brick is present in this wall. */
    bool Contains(const CBrickIndex *pindex) const {
        return (*this)[pindex->nHeight] == pindex;
    }

    /** Find the successor of a brick in this wall, or NULL if the given index is not found or is the tip. */
    CBrickIndex *Next(const CBrickIndex *pindex) const {
        if (Contains(pindex))
            return (*this)[pindex->nHeight + 1];
        else
            return NULL;
    }

    /** Return the maximal height in the wall. Is equal to wall.Tip() ? wall.Tip()->nHeight : -1. */
    int Height() const {
        return vWall.size() - 1;
    }

    /** Set/initialize a wall with a given tip. */
    void SetTip(CBrickIndex *pindex);

    /** Return a CBrickLocator that refers to a brick in this wall (by default the tip). */
    CBrickLocator GetLocator(const CBrickIndex *pindex = NULL) const;

    /** Find the last common brick between this wall and a brick index entry. */
    const CBrickIndex *FindFork(const CBrickIndex *pindex) const;
};

#endif // BITCOIN_WALL_H
