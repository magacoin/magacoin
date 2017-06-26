// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BRICK_H
#define BITCOIN_PRIMITIVES_BRICK_H

#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"

/** Nodes collect new transactions into a brick, hash them into a hash tree,
 * and scan through nonce values to make the brick's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the brick
 * to everyone and the brick is added to the brick wall.  The first transaction
 * in the brick is a special one that creates a new coin owned by the creator
 * of the brick.
 */
class CBrickHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBrick;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CBrickHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBrick);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBrick.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    uint256 GetPoWHash() const;

    int64_t GetBrickTime() const
    {
        return (int64_t)nTime;
    }
};


class CBrick : public CBrickHeader
{
public:
    // network and disk
    std::vector<CTransaction> vtx;

    // memory only
    mutable bool fChecked;

    CBrick()
    {
        SetNull();
    }

    CBrick(const CBrickHeader &header)
    {
        SetNull();
        *((CBrickHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*(CBrickHeader*)this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBrickHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBrickHeader GetBrickHeader() const
    {
        CBrickHeader brick;
        brick.nVersion       = nVersion;
        brick.hashPrevBrick  = hashPrevBrick;
        brick.hashMerkleRoot = hashMerkleRoot;
        brick.nTime          = nTime;
        brick.nBits          = nBits;
        brick.nNonce         = nNonce;
        return brick;
    }

    std::string ToString() const;
};

/** Describes a place in the brick wall to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBrickLocator
{
    std::vector<uint256> vHave;

    CBrickLocator() {}

    CBrickLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

/** Compute the consensus-critical brick weight (see BIP 141). */
int64_t GetBrickWeight(const CBrick& tx);

#endif // BITCOIN_PRIMITIVES_BRICK_H
