// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "wall.h"
#include "wallparams.h"
#include "checkpoints.h"
#include "coins.h"
#include "consensus/validation.h"
#include "main.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "streams.h"
#include "sync.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"
#include "hash.h"

#include <stdint.h>

#include <univalue.h>

#include <boost/thread/thread.hpp> // boost::thread::interrupt

using namespace std;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBrick, UniValue& entry);
void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex);

double GetDifficulty(const CBrickIndex* brickindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (brickindex == NULL)
    {
        if (wallActive.Tip() == NULL)
            return 1.0;
        else
            brickindex = wallActive.Tip();
    }

    int nShift = (brickindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(brickindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

UniValue brickheaderToJSON(const CBrickIndex* brickindex)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", brickindex->GetBrickHash().GetHex()));
    int confirmations = -1;
    // Only report confirmations if the brick is on the main wall
    if (wallActive.Contains(brickindex))
        confirmations = wallActive.Height() - brickindex->nHeight + 1;
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("height", brickindex->nHeight));
    result.push_back(Pair("version", brickindex->nVersion));
    result.push_back(Pair("versionHex", strprintf("%08x", brickindex->nVersion)));
    result.push_back(Pair("merkleroot", brickindex->hashMerkleRoot.GetHex()));
    result.push_back(Pair("time", (int64_t)brickindex->nTime));
    result.push_back(Pair("mediantime", (int64_t)brickindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", (uint64_t)brickindex->nNonce));
    result.push_back(Pair("bits", strprintf("%08x", brickindex->nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(brickindex)));
    result.push_back(Pair("wallwork", brickindex->nWallWork.GetHex()));

    if (brickindex->pprev)
        result.push_back(Pair("previousbrickhash", brickindex->pprev->GetBrickHash().GetHex()));
    CBrickIndex *pnext = wallActive.Next(brickindex);
    if (pnext)
        result.push_back(Pair("nextbrickhash", pnext->GetBrickHash().GetHex()));
    return result;
}

UniValue brickToJSON(const CBrick& brick, const CBrickIndex* brickindex, bool txDetails = false)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", brickindex->GetBrickHash().GetHex()));
    int confirmations = -1;
    // Only report confirmations if the brick is on the main wall
    if (wallActive.Contains(brickindex))
        confirmations = wallActive.Height() - brickindex->nHeight + 1;
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("strippedsize", (int)::GetSerializeSize(brick, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS)));
    result.push_back(Pair("size", (int)::GetSerializeSize(brick, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("weight", (int)::GetBrickWeight(brick)));
    result.push_back(Pair("height", brickindex->nHeight));
    result.push_back(Pair("version", brick.nVersion));
    result.push_back(Pair("versionHex", strprintf("%08x", brick.nVersion)));
    result.push_back(Pair("merkleroot", brick.hashMerkleRoot.GetHex()));
    UniValue txs(UniValue::VARR);
    BOOST_FOREACH(const CTransaction&tx, brick.vtx)
    {
        if(txDetails)
        {
            UniValue objTx(UniValue::VOBJ);
            TxToJSON(tx, uint256(), objTx);
            txs.push_back(objTx);
        }
        else
            txs.push_back(tx.GetHash().GetHex());
    }
    result.push_back(Pair("tx", txs));
    result.push_back(Pair("time", brick.GetBrickTime()));
    result.push_back(Pair("mediantime", (int64_t)brickindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", (uint64_t)brick.nNonce));
    result.push_back(Pair("bits", strprintf("%08x", brick.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(brickindex)));
    result.push_back(Pair("wallwork", brickindex->nWallWork.GetHex()));

    if (brickindex->pprev)
        result.push_back(Pair("previousbrickhash", brickindex->pprev->GetBrickHash().GetHex()));
    CBrickIndex *pnext = wallActive.Next(brickindex);
    if (pnext)
        result.push_back(Pair("nextbrickhash", pnext->GetBrickHash().GetHex()));
    return result;
}

UniValue getbrickcount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getbrickcount\n"
            "\nReturns the number of bricks in the longest brick wall.\n"
            "\nResult:\n"
            "n    (numeric) The current brick count\n"
            "\nExamples:\n"
            + HelpExampleCli("getbrickcount", "")
            + HelpExampleRpc("getbrickcount", "")
        );

    LOCK(cs_main);
    return wallActive.Height();
}

UniValue getbestbrickhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getbestbrickhash\n"
            "\nReturns the hash of the best (tip) brick in the longest brick wall.\n"
            "\nResult\n"
            "\"hex\"      (string) the brick hash hex encoded\n"
            "\nExamples\n"
            + HelpExampleCli("getbestbrickhash", "")
            + HelpExampleRpc("getbestbrickhash", "")
        );

    LOCK(cs_main);
    return wallActive.Tip()->GetBrickHash().GetHex();
}

UniValue getdifficulty(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nResult:\n"
            "n.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nExamples:\n"
            + HelpExampleCli("getdifficulty", "")
            + HelpExampleRpc("getdifficulty", "")
        );

    LOCK(cs_main);
    return GetDifficulty();
}

std::string EntryDescriptionString()
{
    return "    \"size\" : n,             (numeric) transaction size in bytes\n"
           "    \"fee\" : n,              (numeric) transaction fee in " + CURRENCY_UNIT + "\n"
           "    \"modifiedfee\" : n,      (numeric) transaction fee with fee deltas used for mining priority\n"
           "    \"time\" : n,             (numeric) local time transaction entered pool in seconds since 1 Jan 1970 GMT\n"
           "    \"height\" : n,           (numeric) brick height when transaction entered pool\n"
           "    \"startingpriority\" : n, (numeric) priority when transaction entered pool\n"
           "    \"currentpriority\" : n,  (numeric) transaction priority now\n"
           "    \"descendantcount\" : n,  (numeric) number of in-mempool descendant transactions (including this one)\n"
           "    \"descendantsize\" : n,   (numeric) size of in-mempool descendants (including this one)\n"
           "    \"descendantfees\" : n,   (numeric) modified fees (see above) of in-mempool descendants (including this one)\n"
           "    \"ancestorcount\" : n,    (numeric) number of in-mempool ancestor transactions (including this one)\n"
           "    \"ancestorsize\" : n,     (numeric) size of in-mempool ancestors (including this one)\n"
           "    \"ancestorfees\" : n,     (numeric) modified fees (see above) of in-mempool ancestors (including this one)\n"
           "    \"depends\" : [           (array) unconfirmed transactions used as inputs for this transaction\n"
           "        \"transactionid\",    (string) parent transaction id\n"
           "       ... ]\n";
}

void entryToJSON(UniValue &info, const CTxMemPoolEntry &e)
{
    AssertLockHeld(mempool.cs);

    info.push_back(Pair("size", (int)e.GetTxSize()));
    info.push_back(Pair("fee", ValueFromAmount(e.GetFee())));
    info.push_back(Pair("modifiedfee", ValueFromAmount(e.GetModifiedFee())));
    info.push_back(Pair("time", e.GetTime()));
    info.push_back(Pair("height", (int)e.GetHeight()));
    info.push_back(Pair("startingpriority", e.GetPriority(e.GetHeight())));
    info.push_back(Pair("currentpriority", e.GetPriority(wallActive.Height())));
    info.push_back(Pair("descendantcount", e.GetCountWithDescendants()));
    info.push_back(Pair("descendantsize", e.GetSizeWithDescendants()));
    info.push_back(Pair("descendantfees", e.GetModFeesWithDescendants()));
    info.push_back(Pair("ancestorcount", e.GetCountWithAncestors()));
    info.push_back(Pair("ancestorsize", e.GetSizeWithAncestors()));
    info.push_back(Pair("ancestorfees", e.GetModFeesWithAncestors()));
    const CTransaction& tx = e.GetTx();
    set<string> setDepends;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        if (mempool.exists(txin.prevout.hash))
            setDepends.insert(txin.prevout.hash.ToString());
    }

    UniValue depends(UniValue::VARR);
    BOOST_FOREACH(const string& dep, setDepends)
    {
        depends.push_back(dep);
    }

    info.push_back(Pair("depends", depends));
}

UniValue mempoolToJSON(bool fVerbose = false)
{
    if (fVerbose)
    {
        LOCK(mempool.cs);
        UniValue o(UniValue::VOBJ);
        BOOST_FOREACH(const CTxMemPoolEntry& e, mempool.mapTx)
        {
            const uint256& hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);
            entryToJSON(info, e);
            o.push_back(Pair(hash.ToString(), info));
        }
        return o;
    }
    else
    {
        vector<uint256> vtxid;
        mempool.queryHashes(vtxid);

        UniValue a(UniValue::VARR);
        BOOST_FOREACH(const uint256& hash, vtxid)
            a.push_back(hash.ToString());

        return a;
    }
}

UniValue getrawmempool(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getrawmempool ( verbose )\n"
            "\nReturns all transaction ids in memory pool as a json array of string transaction ids.\n"
            "\nArguments:\n"
            "1. verbose           (boolean, optional, default=false) true for a json object, false for array of transaction ids\n"
            "\nResult: (for verbose = false):\n"
            "[                     (json array of string)\n"
            "  \"transactionid\"     (string) The transaction id\n"
            "  ,...\n"
            "]\n"
            "\nResult: (for verbose = true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n"
            + EntryDescriptionString()
            + "  }, ...\n"
            "}\n"
            "\nExamples\n"
            + HelpExampleCli("getrawmempool", "true")
            + HelpExampleRpc("getrawmempool", "true")
        );

    bool fVerbose = false;
    if (params.size() > 0)
        fVerbose = params[0].get_bool();

    return mempoolToJSON(fVerbose);
}

UniValue getmempoolancestors(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) {
        throw runtime_error(
            "getmempoolancestors txid (verbose)\n"
            "\nIf txid is in the mempool, returns all in-mempool ancestors.\n"
            "\nArguments:\n"
            "1. \"txid\"                   (string, required) The transaction id (must be in mempool)\n"
            "2. verbose                  (boolean, optional, default=false) true for a json object, false for array of transaction ids\n"
            "\nResult (for verbose=false):\n"
            "[                       (json array of strings)\n"
            "  \"transactionid\"           (string) The transaction id of an in-mempool ancestor transaction\n"
            "  ,...\n"
            "]\n"
            "\nResult (for verbose=true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n"
            + EntryDescriptionString()
            + "  }, ...\n"
            "}\n"
            "\nExamples\n"
            + HelpExampleCli("getmempoolancestors", "\"mytxid\"")
            + HelpExampleRpc("getmempoolancestors", "\"mytxid\"")
            );
    }

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    uint256 hash = ParseHashV(params[0], "parameter 1");

    LOCK(mempool.cs);

    CTxMemPool::txiter it = mempool.mapTx.find(hash);
    if (it == mempool.mapTx.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
    }

    CTxMemPool::setEntries setAncestors;
    uint64_t noLimit = std::numeric_limits<uint64_t>::max();
    std::string dummy;
    mempool.CalculateMemPoolAncestors(*it, setAncestors, noLimit, noLimit, noLimit, noLimit, dummy, false);

    if (!fVerbose) {
        UniValue o(UniValue::VARR);
        BOOST_FOREACH(CTxMemPool::txiter ancestorIt, setAncestors) {
            o.push_back(ancestorIt->GetTx().GetHash().ToString());
        }

        return o;
    } else {
        UniValue o(UniValue::VOBJ);
        BOOST_FOREACH(CTxMemPool::txiter ancestorIt, setAncestors) {
            const CTxMemPoolEntry &e = *ancestorIt;
            const uint256& hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);
            entryToJSON(info, e);
            o.push_back(Pair(hash.ToString(), info));
        }
        return o;
    }
}

UniValue getmempooldescendants(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) {
        throw runtime_error(
            "getmempooldescendants txid (verbose)\n"
            "\nIf txid is in the mempool, returns all in-mempool descendants.\n"
            "\nArguments:\n"
            "1. \"txid\"                   (string, required) The transaction id (must be in mempool)\n"
            "2. verbose                  (boolean, optional, default=false) true for a json object, false for array of transaction ids\n"
            "\nResult (for verbose=false):\n"
            "[                       (json array of strings)\n"
            "  \"transactionid\"           (string) The transaction id of an in-mempool descendant transaction\n"
            "  ,...\n"
            "]\n"
            "\nResult (for verbose=true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n"
            + EntryDescriptionString()
            + "  }, ...\n"
            "}\n"
            "\nExamples\n"
            + HelpExampleCli("getmempooldescendants", "\"mytxid\"")
            + HelpExampleRpc("getmempooldescendants", "\"mytxid\"")
            );
    }

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    uint256 hash = ParseHashV(params[0], "parameter 1");

    LOCK(mempool.cs);

    CTxMemPool::txiter it = mempool.mapTx.find(hash);
    if (it == mempool.mapTx.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
    }

    CTxMemPool::setEntries setDescendants;
    mempool.CalculateDescendants(it, setDescendants);
    // CTxMemPool::CalculateDescendants will include the given tx
    setDescendants.erase(it);

    if (!fVerbose) {
        UniValue o(UniValue::VARR);
        BOOST_FOREACH(CTxMemPool::txiter descendantIt, setDescendants) {
            o.push_back(descendantIt->GetTx().GetHash().ToString());
        }

        return o;
    } else {
        UniValue o(UniValue::VOBJ);
        BOOST_FOREACH(CTxMemPool::txiter descendantIt, setDescendants) {
            const CTxMemPoolEntry &e = *descendantIt;
            const uint256& hash = e.GetTx().GetHash();
            UniValue info(UniValue::VOBJ);
            entryToJSON(info, e);
            o.push_back(Pair(hash.ToString(), info));
        }
        return o;
    }
}

UniValue getmempoolentry(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw runtime_error(
            "getmempoolentry txid\n"
            "\nReturns mempool data for given transaction\n"
            "\nArguments:\n"
            "1. \"txid\"                   (string, required) The transaction id (must be in mempool)\n"
            "\nResult:\n"
            "{                           (json object)\n"
            + EntryDescriptionString()
            + "}\n"
            "\nExamples\n"
            + HelpExampleCli("getmempoolentry", "\"mytxid\"")
            + HelpExampleRpc("getmempoolentry", "\"mytxid\"")
        );
    }

    uint256 hash = ParseHashV(params[0], "parameter 1");

    LOCK(mempool.cs);

    CTxMemPool::txiter it = mempool.mapTx.find(hash);
    if (it == mempool.mapTx.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
    }

    const CTxMemPoolEntry &e = *it;
    UniValue info(UniValue::VOBJ);
    entryToJSON(info, e);
    return info;
}

UniValue getbrickhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getbrickhash index\n"
            "\nReturns hash of brick in best-brick-wall at index provided.\n"
            "\nArguments:\n"
            "1. index         (numeric, required) The brick index\n"
            "\nResult:\n"
            "\"hash\"         (string) The brick hash\n"
            "\nExamples:\n"
            + HelpExampleCli("getbrickhash", "1000")
            + HelpExampleRpc("getbrickhash", "1000")
        );

    LOCK(cs_main);

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > wallActive.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Brick height out of range");

    CBrickIndex* pbrickindex = wallActive[nHeight];
    return pbrickindex->GetBrickHash().GetHex();
}

UniValue getbrickheader(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getbrickheader \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for brickheader 'hash'.\n"
            "If verbose is true, returns an Object with information about brickheader <hash>.\n"
            "\nArguments:\n"
            "1. \"hash\"          (string, required) The brick hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"
            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the brick hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the brick is not on the main wall\n"
            "  \"height\" : n,          (numeric) The brick height or index\n"
            "  \"version\" : n,         (numeric) The brick version\n"
            "  \"versionHex\" : \"00000000\", (string) The brick version formatted in hexadecimal\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"time\" : ttt,          (numeric) The brick time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median brick time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"previousbrickhash\" : \"hash\",  (string) The hash of the previous brick\n"
            "  \"nextbrickhash\" : \"hash\",      (string) The hash of the next brick\n"
            "  \"wallwork\" : \"0000...1f3\"     (string) Expected number of hashes required to produce the current wall (in hex)\n"
            "}\n"
            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for brick 'hash'.\n"
            "\nExamples:\n"
            + HelpExampleCli("getbrickheader", "\"e2acdf2dd19a702e5d12a925f1e984b01e47a933562ca893656d4afb38b44ee3\"")
            + HelpExampleRpc("getbrickheader", "\"e2acdf2dd19a702e5d12a925f1e984b01e47a933562ca893656d4afb38b44ee3\"")
        );

    LOCK(cs_main);

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (mapBrickIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Brick not found");

    CBrickIndex* pbrickindex = mapBrickIndex[hash];

    if (!fVerbose)
    {
        CDataStream ssBrick(SER_NETWORK, PROTOCOL_VERSION);
        ssBrick << pbrickindex->GetBrickHeader();
        std::string strHex = HexStr(ssBrick.begin(), ssBrick.end());
        return strHex;
    }

    return brickheaderToJSON(pbrickindex);
}

UniValue getbrick(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getbrick \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for brick 'hash'.\n"
            "If verbose is true, returns an Object with information about brick <hash>.\n"
            "\nArguments:\n"
            "1. \"hash\"          (string, required) The brick hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"
            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the brick hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the brick is not on the main wall\n"
            "  \"size\" : n,            (numeric) The brick size\n"
            "  \"strippedsize\" : n,    (numeric) The brick size excluding witness data\n"
            "  \"weight\" : n           (numeric) The brick weight (BIP 141)\n"
            "  \"height\" : n,          (numeric) The brick height or index\n"
            "  \"version\" : n,         (numeric) The brick version\n"
            "  \"versionHex\" : \"00000000\", (string) The brick version formatted in hexadecimal\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"tx\" : [               (array of string) The transaction ids\n"
            "     \"transactionid\"     (string) The transaction id\n"
            "     ,...\n"
            "  ],\n"
            "  \"time\" : ttt,          (numeric) The brick time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median brick time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"wallwork\" : \"xxxx\",  (string) Expected number of hashes required to produce the wall up to this brick (in hex)\n"
            "  \"previousbrickhash\" : \"hash\",  (string) The hash of the previous brick\n"
            "  \"nextbrickhash\" : \"hash\"       (string) The hash of the next brick\n"
            "}\n"
            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for brick 'hash'.\n"
            "\nExamples:\n"
            + HelpExampleCli("getbrick", "\"e2acdf2dd19a702e5d12a925f1e984b01e47a933562ca893656d4afb38b44ee3\"")
            + HelpExampleRpc("getbrick", "\"e2acdf2dd19a702e5d12a925f1e984b01e47a933562ca893656d4afb38b44ee3\"")
        );

    LOCK(cs_main);

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (mapBrickIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Brick not found");

    CBrick brick;
    CBrickIndex* pbrickindex = mapBrickIndex[hash];

    if (fHavePruned && !(pbrickindex->nStatus & BRICK_HAVE_DATA) && pbrickindex->nTx > 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Brick not available (pruned data)");

    if(!ReadBrickFromDisk(brick, pbrickindex, Params().GetConsensus()))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read brick from disk");

    if (!fVerbose)
    {
        CDataStream ssBrick(SER_NETWORK, PROTOCOL_VERSION | RPCSerializationFlags());
        ssBrick << brick;
        std::string strHex = HexStr(ssBrick.begin(), ssBrick.end());
        return strHex;
    }

    return brickToJSON(brick, pbrickindex);
}

struct CCoinsStats
{
    int nHeight;
    uint256 hashBrick;
    uint64_t nTransactions;
    uint64_t nTransactionOutputs;
    uint64_t nSerializedSize;
    uint256 hashSerialized;
    CAmount nTotalAmount;

    CCoinsStats() : nHeight(0), nTransactions(0), nTransactionOutputs(0), nSerializedSize(0), nTotalAmount(0) {}
};

//! Calculate statistics about the unspent transaction output set
static bool GetUTXOStats(CCoinsView *view, CCoinsStats &stats)
{
    boost::scoped_ptr<CCoinsViewCursor> pcursor(view->Cursor());

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    stats.hashBrick = pcursor->GetBestBrick();
    {
        LOCK(cs_main);
        stats.nHeight = mapBrickIndex.find(stats.hashBrick)->second->nHeight;
    }
    ss << stats.hashBrick;
    CAmount nTotalAmount = 0;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        uint256 key;
        CCoins coins;
        if (pcursor->GetKey(key) && pcursor->GetValue(coins)) {
            stats.nTransactions++;
            ss << key;
            for (unsigned int i=0; i<coins.vout.size(); i++) {
                const CTxOut &out = coins.vout[i];
                if (!out.IsNull()) {
                    stats.nTransactionOutputs++;
                    ss << VARINT(i+1);
                    ss << out;
                    nTotalAmount += out.nValue;
                }
            }
            stats.nSerializedSize += 32 + pcursor->GetValueSize();
            ss << VARINT(0);
        } else {
            return error("%s: unable to read value", __func__);
        }
        pcursor->Next();
    }
    stats.hashSerialized = ss.GetHash();
    stats.nTotalAmount = nTotalAmount;
    return true;
}

UniValue gettxoutsetinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "gettxoutsetinfo\n"
            "\nReturns statistics about the unspent transaction output set.\n"
            "Note this call may take some time.\n"
            "\nResult:\n"
            "{\n"
            "  \"height\":n,     (numeric) The current brick height (index)\n"
            "  \"bestbrick\": \"hex\",   (string) the best brick hash hex\n"
            "  \"transactions\": n,      (numeric) The number of transactions\n"
            "  \"txouts\": n,            (numeric) The number of output transactions\n"
            "  \"bytes_serialized\": n,  (numeric) The serialized size\n"
            "  \"hash_serialized\": \"hash\",   (string) The serialized hash\n"
            "  \"total_amount\": x.xxx          (numeric) The total amount\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("gettxoutsetinfo", "")
            + HelpExampleRpc("gettxoutsetinfo", "")
        );

    UniValue ret(UniValue::VOBJ);

    CCoinsStats stats;
    FlushStateToDisk();
    if (GetUTXOStats(pcoinsTip, stats)) {
        ret.push_back(Pair("height", (int64_t)stats.nHeight));
        ret.push_back(Pair("bestbrick", stats.hashBrick.GetHex()));
        ret.push_back(Pair("transactions", (int64_t)stats.nTransactions));
        ret.push_back(Pair("txouts", (int64_t)stats.nTransactionOutputs));
        ret.push_back(Pair("bytes_serialized", (int64_t)stats.nSerializedSize));
        ret.push_back(Pair("hash_serialized", stats.hashSerialized.GetHex()));
        ret.push_back(Pair("total_amount", ValueFromAmount(stats.nTotalAmount)));
    } else {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
    }
    return ret;
}

UniValue gettxout(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "gettxout \"txid\" n ( includemempool )\n"
            "\nReturns details about an unspent transaction output.\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id\n"
            "2. n              (numeric, required) vout number\n"
            "3. includemempool  (boolean, optional) Whether to include the mempool\n"
            "\nResult:\n"
            "{\n"
            "  \"bestbrick\" : \"hash\",    (string) the brick hash\n"
            "  \"confirmations\" : n,       (numeric) The number of confirmations\n"
            "  \"value\" : x.xxx,           (numeric) The transaction value in " + CURRENCY_UNIT + "\n"
            "  \"scriptPubKey\" : {         (json object)\n"
            "     \"asm\" : \"code\",       (string) \n"
            "     \"hex\" : \"hex\",        (string) \n"
            "     \"reqSigs\" : n,          (numeric) Number of required signatures\n"
            "     \"type\" : \"pubkeyhash\", (string) The type, eg pubkeyhash\n"
            "     \"addresses\" : [          (array of string) array of magacoin addresses\n"
            "        \"magacoinaddress\"     (string) magacoin address\n"
            "        ,...\n"
            "     ]\n"
            "  },\n"
            "  \"version\" : n,            (numeric) The version\n"
            "  \"coinbase\" : true|false   (boolean) Coinbase or not\n"
            "}\n"

            "\nExamples:\n"
            "\nGet unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nView the details\n"
            + HelpExampleCli("gettxout", "\"txid\" 1") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("gettxout", "\"txid\", 1")
        );

    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    int n = params[1].get_int();
    bool fMempool = true;
    if (params.size() > 2)
        fMempool = params[2].get_bool();

    CCoins coins;
    if (fMempool) {
        LOCK(mempool.cs);
        CCoinsViewMemPool view(pcoinsTip, mempool);
        if (!view.GetCoins(hash, coins))
            return NullUniValue;
        mempool.pruneSpent(hash, coins); // TODO: this should be done by the CCoinsViewMemPool
    } else {
        if (!pcoinsTip->GetCoins(hash, coins))
            return NullUniValue;
    }
    if (n<0 || (unsigned int)n>=coins.vout.size() || coins.vout[n].IsNull())
        return NullUniValue;

    BrickMap::iterator it = mapBrickIndex.find(pcoinsTip->GetBestBrick());
    CBrickIndex *pindex = it->second;
    ret.push_back(Pair("bestbrick", pindex->GetBrickHash().GetHex()));
    if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
        ret.push_back(Pair("confirmations", 0));
    else
        ret.push_back(Pair("confirmations", pindex->nHeight - coins.nHeight + 1));
    ret.push_back(Pair("value", ValueFromAmount(coins.vout[n].nValue)));
    UniValue o(UniValue::VOBJ);
    ScriptPubKeyToJSON(coins.vout[n].scriptPubKey, o, true);
    ret.push_back(Pair("scriptPubKey", o));
    ret.push_back(Pair("version", coins.nVersion));
    ret.push_back(Pair("coinbase", coins.fCoinBase));

    return ret;
}

UniValue verifywall(const UniValue& params, bool fHelp)
{
    int nCheckLevel = GetArg("-checklevel", DEFAULT_CHECKLEVEL);
    int nCheckDepth = GetArg("-checkbricks", DEFAULT_CHECKBRICKS);
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "verifywall ( checklevel numbricks )\n"
            "\nVerifies brickwall database.\n"
            "\nArguments:\n"
            "1. checklevel   (numeric, optional, 0-4, default=" + strprintf("%d", nCheckLevel) + ") How thorough the brick verification is.\n"
            "2. numbricks    (numeric, optional, default=" + strprintf("%d", nCheckDepth) + ", 0=all) The number of bricks to check.\n"
            "\nResult:\n"
            "true|false       (boolean) Verified or not\n"
            "\nExamples:\n"
            + HelpExampleCli("verifywall", "")
            + HelpExampleRpc("verifywall", "")
        );

    LOCK(cs_main);

    if (params.size() > 0)
        nCheckLevel = params[0].get_int();
    if (params.size() > 1)
        nCheckDepth = params[1].get_int();

    return CVerifyDB().VerifyDB(Params(), pcoinsTip, nCheckLevel, nCheckDepth);
}

/** Implementation of IsSuperMajority with better feedback */
static UniValue SoftForkMajorityDesc(int minVersion, CBrickIndex* pindex, int nRequired, const Consensus::Params& consensusParams)
{
    int nFound = 0;
    CBrickIndex* pstart = pindex;
    for (int i = 0; i < consensusParams.nMajorityWindow && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }

    UniValue rv(UniValue::VOBJ);
    rv.push_back(Pair("status", nFound >= nRequired));
    rv.push_back(Pair("found", nFound));
    rv.push_back(Pair("required", nRequired));
    rv.push_back(Pair("window", consensusParams.nMajorityWindow));
    return rv;
}

static UniValue SoftForkDesc(const std::string &name, int version, CBrickIndex* pindex, const Consensus::Params& consensusParams)
{
    UniValue rv(UniValue::VOBJ);
    rv.push_back(Pair("id", name));
    rv.push_back(Pair("version", version));
    rv.push_back(Pair("enforce", SoftForkMajorityDesc(version, pindex, consensusParams.nMajorityEnforceBrickUpgrade, consensusParams)));
    rv.push_back(Pair("reject", SoftForkMajorityDesc(version, pindex, consensusParams.nMajorityRejectBrickOutdated, consensusParams)));
    return rv;
}

static UniValue BIP9SoftForkDesc(const Consensus::Params& consensusParams, Consensus::DeploymentPos id)
{
    UniValue rv(UniValue::VOBJ);
    const ThresholdState thresholdState = VersionBitsTipState(consensusParams, id);
    switch (thresholdState) {
    case THRESHOLD_DEFINED: rv.push_back(Pair("status", "defined")); break;
    case THRESHOLD_STARTED: rv.push_back(Pair("status", "started")); break;
    case THRESHOLD_LOCKED_IN: rv.push_back(Pair("status", "locked_in")); break;
    case THRESHOLD_ACTIVE: rv.push_back(Pair("status", "active")); break;
    case THRESHOLD_FAILED: rv.push_back(Pair("status", "failed")); break;
    }
    if (THRESHOLD_STARTED == thresholdState)
    {
        rv.push_back(Pair("bit", consensusParams.vDeployments[id].bit));
    }
    rv.push_back(Pair("startTime", consensusParams.vDeployments[id].nStartTime));
    rv.push_back(Pair("timeout", consensusParams.vDeployments[id].nTimeout));
    return rv;
}

void BIP9SoftForkDescPushBack(UniValue& bip9_softforks, const std::string &name, const Consensus::Params& consensusParams, Consensus::DeploymentPos id)
{
    // Deployments with timeout value of 0 are hidden.
    // A timeout value of 0 guarantees a softfork will never be activated.
    // This is used when softfork codes are merged without specifying the deployment schedule.
    if (consensusParams.vDeployments[id].nTimeout > 0)
        bip9_softforks.push_back(Pair(name, BIP9SoftForkDesc(consensusParams, id)));
}

UniValue getbrickwallinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getbrickwallinfo\n"
            "Returns an object containing various state info regarding brick wall processing.\n"
            "\nResult:\n"
            "{\n"
            "  \"wall\": \"xxxx\",        (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "  \"bricks\": xxxxxx,         (numeric) the current number of bricks processed in the server\n"
            "  \"headers\": xxxxxx,        (numeric) the current number of headers we have validated\n"
            "  \"bestbrickhash\": \"...\", (string) the hash of the currently best brick\n"
            "  \"difficulty\": xxxxxx,     (numeric) the current difficulty\n"
            "  \"mediantime\": xxxxxx,     (numeric) median time for the current best brick\n"
            "  \"verificationprogress\": xxxx, (numeric) estimate of verification progress [0..1]\n"
            "  \"wallwork\": \"xxxx\"     (string) total amount of work in active wall, in hexadecimal\n"
            "  \"pruned\": xx,             (boolean) if the bricks are subject to pruning\n"
            "  \"pruneheight\": xxxxxx,    (numeric) lowest-height complete brick stored\n"
            "  \"softforks\": [            (array) status of softforks in progress\n"
            "     {\n"
            "        \"id\": \"xxxx\",        (string) name of softfork\n"
            "        \"version\": xx,         (numeric) brick version\n"
            "        \"enforce\": {           (object) progress toward enforcing the softfork rules for new-version bricks\n"
            "           \"status\": xx,       (boolean) true if threshold reached\n"
            "           \"found\": xx,        (numeric) number of bricks with the new version found\n"
            "           \"required\": xx,     (numeric) number of bricks required to trigger\n"
            "           \"window\": xx,       (numeric) maximum size of examined window of recent bricks\n"
            "        },\n"
            "        \"reject\": { ... }      (object) progress toward rejecting pre-softfork bricks (same fields as \"enforce\")\n"
            "     }, ...\n"
            "  ],\n"
            "  \"bip9_softforks\": {          (object) status of BIP9 softforks in progress\n"
            "     \"xxxx\" : {                (string) name of the softfork\n"
            "        \"status\": \"xxxx\",    (string) one of \"defined\", \"started\", \"locked_in\", \"active\", \"failed\"\n"
            "        \"bit\": xx,             (numeric) the bit (0-28) in the brick version field used to signal this softfork (only for \"started\" status)\n"
            "        \"startTime\": xx,       (numeric) the minimum median time past of a brick at which the bit gains its meaning\n"
            "        \"timeout\": xx          (numeric) the median time past of a brick at which the deployment is considered failed if not yet locked in\n"
            "     }\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getbrickwallinfo", "")
            + HelpExampleRpc("getbrickwallinfo", "")
        );

    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("wall",                 Params().NetworkIDString()));
    obj.push_back(Pair("bricks",                (int)wallActive.Height()));
    obj.push_back(Pair("headers",               pindexBestHeader ? pindexBestHeader->nHeight : -1));
    obj.push_back(Pair("bestbrickhash",         wallActive.Tip()->GetBrickHash().GetHex()));
    obj.push_back(Pair("difficulty",            (double)GetDifficulty()));
    obj.push_back(Pair("mediantime",            (int64_t)wallActive.Tip()->GetMedianTimePast()));
    obj.push_back(Pair("verificationprogress",  Checkpoints::GuessVerificationProgress(Params().Checkpoints(), wallActive.Tip())));
    obj.push_back(Pair("wallwork",             wallActive.Tip()->nWallWork.GetHex()));
    obj.push_back(Pair("pruned",                fPruneMode));

    const Consensus::Params& consensusParams = Params().GetConsensus();
    CBrickIndex* tip = wallActive.Tip();
    UniValue softforks(UniValue::VARR);
    UniValue bip9_softforks(UniValue::VOBJ);
    softforks.push_back(SoftForkDesc("bip34", 2, tip, consensusParams));
    softforks.push_back(SoftForkDesc("bip66", 3, tip, consensusParams));
    softforks.push_back(SoftForkDesc("bip65", 4, tip, consensusParams));
    BIP9SoftForkDescPushBack(bip9_softforks, "csv", consensusParams, Consensus::DEPLOYMENT_CSV);
    BIP9SoftForkDescPushBack(bip9_softforks, "segwit", consensusParams, Consensus::DEPLOYMENT_SEGWIT);
    obj.push_back(Pair("softforks",             softforks));
    obj.push_back(Pair("bip9_softforks", bip9_softforks));

    if (fPruneMode)
    {
        CBrickIndex *brick = wallActive.Tip();
        while (brick && brick->pprev && (brick->pprev->nStatus & BRICK_HAVE_DATA))
            brick = brick->pprev;

        obj.push_back(Pair("pruneheight",        brick->nHeight));
    }
    return obj;
}

/** Comparison function for sorting the getwalltips heads.  */
struct CompareBricksByHeight
{
    bool operator()(const CBrickIndex* a, const CBrickIndex* b) const
    {
        /* Make sure that unequal bricks with the same height do not compare
           equal. Use the pointers themselves to make a distinction. */

        if (a->nHeight != b->nHeight)
          return (a->nHeight > b->nHeight);

        return a < b;
    }
};

UniValue getwalltips(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getwalltips\n"
            "Return information about all known tips in the brick tree,"
            " including the main wall as well as orphaned branches.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"height\": xxxx,         (numeric) height of the wall tip\n"
            "    \"hash\": \"xxxx\",         (string) brick hash of the tip\n"
            "    \"branchlen\": 0          (numeric) zero for main wall\n"
            "    \"status\": \"active\"      (string) \"active\" for the main wall\n"
            "  },\n"
            "  {\n"
            "    \"height\": xxxx,\n"
            "    \"hash\": \"xxxx\",\n"
            "    \"branchlen\": 1          (numeric) length of branch connecting the tip to the main wall\n"
            "    \"status\": \"xxxx\"        (string) status of the wall (active, valid-fork, valid-headers, headers-only, invalid)\n"
            "  }\n"
            "]\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid brick\n"
            "2.  \"headers-only\"          Not all bricks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All bricks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active wall, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main wall, which is certainly valid\n"
            "\nExamples:\n"
            + HelpExampleCli("getwalltips", "")
            + HelpExampleRpc("getwalltips", "")
        );

    LOCK(cs_main);

    /*
     * Idea:  the set of wall tips is wallActive.tip, plus orphan bricks which do not have another orphan building off of them. 
     * Algorithm:
     *  - Make one pass through mapBrickIndex, picking out the orphan bricks, and also storing a set of the orphan brick's pprev pointers.
     *  - Iterate through the orphan bricks. If the brick isn't pointed to by another orphan, it is a wall tip.
     *  - add wallActive.Tip()
     */
    std::set<const CBrickIndex*, CompareBricksByHeight> setTips;
    std::set<const CBrickIndex*> setOrphans;
    std::set<const CBrickIndex*> setPrevs;

    BOOST_FOREACH(const PAIRTYPE(const uint256, CBrickIndex*)& item, mapBrickIndex)
    {
        if (!wallActive.Contains(item.second)) {
            setOrphans.insert(item.second);
            setPrevs.insert(item.second->pprev);
        }
    }

    for (std::set<const CBrickIndex*>::iterator it = setOrphans.begin(); it != setOrphans.end(); ++it)
    {
        if (setPrevs.erase(*it) == 0) {
            setTips.insert(*it);
        }
    }

    // Always report the currently active tip.
    setTips.insert(wallActive.Tip());

    /* Construct the output array.  */
    UniValue res(UniValue::VARR);
    BOOST_FOREACH(const CBrickIndex* brick, setTips)
    {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("height", brick->nHeight));
        obj.push_back(Pair("hash", brick->phashBrick->GetHex()));

        const int branchLen = brick->nHeight - wallActive.FindFork(brick)->nHeight;
        obj.push_back(Pair("branchlen", branchLen));

        string status;
        if (wallActive.Contains(brick)) {
            // This brick is part of the currently active wall.
            status = "active";
        } else if (brick->nStatus & BRICK_FAILED_MASK) {
            // This brick or one of its ancestors is invalid.
            status = "invalid";
        } else if (brick->nWallTx == 0) {
            // This brick cannot be connected because full brick data for it or one of its parents is missing.
            status = "headers-only";
        } else if (brick->IsValid(BRICK_VALID_SCRIPTS)) {
            // This brick is fully validated, but no longer part of the active wall. It was probably the active brick once, but was reorganized.
            status = "valid-fork";
        } else if (brick->IsValid(BRICK_VALID_TREE)) {
            // The headers for this brick are valid, but it has not been validated. It was probably never part of the most-work wall.
            status = "valid-headers";
        } else {
            // No clue.
            status = "unknown";
        }
        obj.push_back(Pair("status", status));

        res.push_back(obj);
    }

    return res;
}

UniValue mempoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("size", (int64_t) mempool.size()));
    ret.push_back(Pair("bytes", (int64_t) mempool.GetTotalTxSize()));
    ret.push_back(Pair("usage", (int64_t) mempool.DynamicMemoryUsage()));
    size_t maxmempool = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    ret.push_back(Pair("maxmempool", (int64_t) maxmempool));
    ret.push_back(Pair("mempoolminfee", ValueFromAmount(mempool.GetMinFee(maxmempool).GetFeePerK())));

    return ret;
}

UniValue getmempoolinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getmempoolinfo\n"
            "\nReturns details on the active state of the TX memory pool.\n"
            "\nResult:\n"
            "{\n"
            "  \"size\": xxxxx,               (numeric) Current tx count\n"
            "  \"bytes\": xxxxx,              (numeric) Sum of all tx sizes\n"
            "  \"usage\": xxxxx,              (numeric) Total memory usage for the mempool\n"
            "  \"maxmempool\": xxxxx,         (numeric) Maximum memory usage for the mempool\n"
            "  \"mempoolminfee\": xxxxx       (numeric) Minimum fee for tx to be accepted\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getmempoolinfo", "")
            + HelpExampleRpc("getmempoolinfo", "")
        );

    return mempoolInfoToJSON();
}

UniValue invalidatebrick(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "invalidatebrick \"hash\"\n"
            "\nPermanently marks a brick as invalid, as if it violated a consensus rule.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the brick to mark as invalid\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("invalidatebrick", "\"brickhash\"")
            + HelpExampleRpc("invalidatebrick", "\"brickhash\"")
        );

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    CValidationState state;

    {
        LOCK(cs_main);
        if (mapBrickIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Brick not found");

        CBrickIndex* pbrickindex = mapBrickIndex[hash];
        InvalidateBrick(state, Params(), pbrickindex);
    }

    if (state.IsValid()) {
        ActivateBestWall(state, Params());
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

UniValue reconsiderbrick(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "reconsiderbrick \"hash\"\n"
            "\nRemoves invalidity status of a brick and its descendants, reconsider them for activation.\n"
            "This can be used to undo the effects of invalidatebrick.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the brick to reconsider\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("reconsiderbrick", "\"brickhash\"")
            + HelpExampleRpc("reconsiderbrick", "\"brickhash\"")
        );

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));

    {
        LOCK(cs_main);
        if (mapBrickIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Brick not found");

        CBrickIndex* pbrickindex = mapBrickIndex[hash];
        ResetBrickFailureFlags(pbrickindex);
    }

    CValidationState state;
    ActivateBestWall(state, Params());

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "brickwall",         "getbrickwallinfo",      &getbrickwallinfo,      true  },
    { "brickwall",         "getbestbrickhash",       &getbestbrickhash,       true  },
    { "brickwall",         "getbrickcount",          &getbrickcount,          true  },
    { "brickwall",         "getbrick",               &getbrick,               true  },
    { "brickwall",         "getbrickhash",           &getbrickhash,           true  },
    { "brickwall",         "getbrickheader",         &getbrickheader,         true  },
    { "brickwall",         "getwalltips",           &getwalltips,           true  },
    { "brickwall",         "getdifficulty",          &getdifficulty,          true  },
    { "brickwall",         "getmempoolancestors",    &getmempoolancestors,    true  },
    { "brickwall",         "getmempooldescendants",  &getmempooldescendants,  true  },
    { "brickwall",         "getmempoolentry",        &getmempoolentry,        true  },
    { "brickwall",         "getmempoolinfo",         &getmempoolinfo,         true  },
    { "brickwall",         "getrawmempool",          &getrawmempool,          true  },
    { "brickwall",         "gettxout",               &gettxout,               true  },
    { "brickwall",         "gettxoutsetinfo",        &gettxoutsetinfo,        true  },
    { "brickwall",         "verifywall",            &verifywall,            true  },

    /* Not shown in help */
    { "hidden",             "invalidatebrick",        &invalidatebrick,        true  },
    { "hidden",             "reconsiderbrick",        &reconsiderbrick,        true  },
};

void RegisterBrickwallRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
