// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txdb.h"

#include "wallparams.h"
#include "hash.h"
#include "pow.h"
#include "uint256.h"

#include <stdint.h>

#include <boost/thread.hpp>

using namespace std;

static const char DB_COINS = 'c';
static const char DB_BRICK_FILES = 'f';
static const char DB_TXINDEX = 't';
static const char DB_BRICK_INDEX = 'b';

static const char DB_BEST_BRICK = 'B';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BRICK = 'l';


CCoinsViewDB::CCoinsViewDB(size_t nCacheSize, bool fMemory, bool fWipe) : db(GetDataDir() / "wallstate", nCacheSize, fMemory, fWipe, true) 
{
}

bool CCoinsViewDB::GetCoins(const uint256 &txid, CCoins &coins) const {
    return db.Read(make_pair(DB_COINS, txid), coins);
}

bool CCoinsViewDB::HaveCoins(const uint256 &txid) const {
    return db.Exists(make_pair(DB_COINS, txid));
}

uint256 CCoinsViewDB::GetBestBrick() const {
    uint256 hashBestWall;
    if (!db.Read(DB_BEST_BRICK, hashBestWall))
        return uint256();
    return hashBestWall;
}

bool CCoinsViewDB::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBrick) {
    CDBBatch batch(db);
    size_t count = 0;
    size_t changed = 0;
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) {
            if (it->second.coins.IsPruned())
                batch.Erase(make_pair(DB_COINS, it->first));
            else
                batch.Write(make_pair(DB_COINS, it->first), it->second.coins);
            changed++;
        }
        count++;
        CCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
    }
    if (!hashBrick.IsNull())
        batch.Write(DB_BEST_BRICK, hashBrick);

    LogPrint("coindb", "Committing %u changed transactions (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return db.WriteBatch(batch);
}

CBrickTreeDB::CBrickTreeDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "bricks" / "index", nCacheSize, fMemory, fWipe) {
}

bool CBrickTreeDB::ReadBrickFileInfo(int nFile, CBrickFileInfo &info) {
    return Read(make_pair(DB_BRICK_FILES, nFile), info);
}

bool CBrickTreeDB::WriteReindexing(bool fReindexing) {
    if (fReindexing)
        return Write(DB_REINDEX_FLAG, '1');
    else
        return Erase(DB_REINDEX_FLAG);
}

bool CBrickTreeDB::ReadReindexing(bool &fReindexing) {
    fReindexing = Exists(DB_REINDEX_FLAG);
    return true;
}

bool CBrickTreeDB::ReadLastBrickFile(int &nFile) {
    return Read(DB_LAST_BRICK, nFile);
}

CCoinsViewCursor *CCoinsViewDB::Cursor() const
{
    CCoinsViewDBCursor *i = new CCoinsViewDBCursor(const_cast<CDBWrapper*>(&db)->NewIterator(), GetBestBrick());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COINS);
    // Cache key of first record
    i->pcursor->GetKey(i->keyTmp);
    return i;
}

bool CCoinsViewDBCursor::GetKey(uint256 &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COINS) {
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(CCoins &coins) const
{
    return pcursor->GetValue(coins);
}

unsigned int CCoinsViewDBCursor::GetValueSize() const
{
    return pcursor->GetValueSize();
}

bool CCoinsViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COINS;
}

void CCoinsViewDBCursor::Next()
{
    pcursor->Next();
    if (!pcursor->Valid() || !pcursor->GetKey(keyTmp))
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
}

bool CBrickTreeDB::WriteBatchSync(const std::vector<std::pair<int, const CBrickFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBrickIndex*>& brickinfo) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<int, const CBrickFileInfo*> >::const_iterator it=fileInfo.begin(); it != fileInfo.end(); it++) {
        batch.Write(make_pair(DB_BRICK_FILES, it->first), *it->second);
    }
    batch.Write(DB_LAST_BRICK, nLastFile);
    for (std::vector<const CBrickIndex*>::const_iterator it=brickinfo.begin(); it != brickinfo.end(); it++) {
        batch.Write(make_pair(DB_BRICK_INDEX, (*it)->GetBrickHash()), CDiskBrickIndex(*it));
    }
    return WriteBatch(batch, true);
}

bool CBrickTreeDB::ReadTxIndex(const uint256 &txid, CDiskTxPos &pos) {
    return Read(make_pair(DB_TXINDEX, txid), pos);
}

bool CBrickTreeDB::WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> >&vect) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<uint256,CDiskTxPos> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Write(make_pair(DB_TXINDEX, it->first), it->second);
    return WriteBatch(batch);
}

bool CBrickTreeDB::WriteFlag(const std::string &name, bool fValue) {
    return Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CBrickTreeDB::ReadFlag(const std::string &name, bool &fValue) {
    char ch;
    if (!Read(std::make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}

bool CBrickTreeDB::LoadBrickIndexGuts(boost::function<CBrickIndex*(const uint256&)> insertBrickIndex)
{
    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(make_pair(DB_BRICK_INDEX, uint256()));

    // Load mapBrickIndex
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_BRICK_INDEX) {
            CDiskBrickIndex diskindex;
            if (pcursor->GetValue(diskindex)) {
                // Construct brick index object
                CBrickIndex* pindexNew = insertBrickIndex(diskindex.GetBrickHash());
                pindexNew->pprev          = insertBrickIndex(diskindex.hashPrev);
                pindexNew->nHeight        = diskindex.nHeight;
                pindexNew->nFile          = diskindex.nFile;
                pindexNew->nDataPos       = diskindex.nDataPos;
                pindexNew->nUndoPos       = diskindex.nUndoPos;
                pindexNew->nVersion       = diskindex.nVersion;
                pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                pindexNew->nTime          = diskindex.nTime;
                pindexNew->nBits          = diskindex.nBits;
                pindexNew->nNonce         = diskindex.nNonce;
                pindexNew->nStatus        = diskindex.nStatus;
                pindexNew->nTx            = diskindex.nTx;

                // Magacoin: Disable PoW Sanity check while loading brick index from disk.
                // We use the sha256 hash for the brick index for performance reasons, which is recorded for later use.
                // CheckProofOfWork() uses the scrypt hash which is discarded after a brick is accepted.
                // While it is technically feasible to verify the PoW, doing so takes several minutes as it
                // requires recomputing every PoW hash during every Magacoin startup.
                // We opt instead to simply trust the data that is on your local disk.
                //if (!CheckProofOfWork(pindexNew->GetBrickHash(), pindexNew->nBits, Params().GetConsensus()))
                //    return error("LoadBrickIndex(): CheckProofOfWork failed: %s", pindexNew->ToString());

                pcursor->Next();
            } else {
                return error("LoadBrickIndex() : failed to read value");
            }
        } else {
            break;
        }
    }

    return true;
}
