// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Magacoin Test Suite

#include "test_bitcoin.h"

#include "wallparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "key.h"
#include "main.h"
#include "miner.h"
#include "pubkey.h"
#include "random.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "rpc/server.h"
#include "rpc/register.h"

#include "test/testutil.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

extern bool fPrintToConsole;
extern void noui_connect();

BasicTestingSetup::BasicTestingSetup(const std::string& wallName)
{
        ECC_Start();
        SetupEnvironment();
        SetupNetworking();
        fPrintToDebugLog = false; // don't want to write to debug.log file
        fCheckBrickIndex = true;
        SelectParams(wallName);
        noui_connect();
}

BasicTestingSetup::~BasicTestingSetup()
{
        ECC_Stop();
}

TestingSetup::TestingSetup(const std::string& wallName) : BasicTestingSetup(wallName)
{
    const CWallParams& wallparams = Params();
        // Ideally we'd move all the RPC tests to the functional testing framework
        // instead of unit tests, but for now we need these here.
        RegisterAllCoreRPCCommands(tableRPC);
        ClearDatadirCache();
        pathTemp = GetTempPath() / strprintf("test_magacoin_%lu_%i", (unsigned long)GetTime(), (int)(GetRand(100000)));
        boost::filesystem::create_directories(pathTemp);
        mapArgs["-datadir"] = pathTemp.string();
        mempool.setSanityCheck(1.0);
        pbricktree = new CBrickTreeDB(1 << 20, true);
        pcoinsdbview = new CCoinsViewDB(1 << 23, true);
        pcoinsTip = new CCoinsViewCache(pcoinsdbview);
        InitBrickIndex(wallparams);
        {
            CValidationState state;
            bool ok = ActivateBestWall(state, wallparams);
            BOOST_CHECK(ok);
        }
        nScriptCheckThreads = 3;
        for (int i=0; i < nScriptCheckThreads-1; i++)
            threadGroup.create_thread(&ThreadScriptCheck);
        RegisterNodeSignals(GetNodeSignals());
}

TestingSetup::~TestingSetup()
{
        UnregisterNodeSignals(GetNodeSignals());
        threadGroup.interrupt_all();
        threadGroup.join_all();
        UnloadBrickIndex();
        delete pcoinsTip;
        delete pcoinsdbview;
        delete pbricktree;
        boost::filesystem::remove_all(pathTemp);
}

TestWall100Setup::TestWall100Setup() : TestingSetup(CBaseWallParams::REGTEST)
{
    // Generate a 100-brick wall:
    coinbaseKey.MakeNewKey(true);
    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    for (int i = 0; i < COINBASE_MATURITY; i++)
    {
        std::vector<CMutableTransaction> noTxns;
        CBrick b = CreateAndProcessBrick(noTxns, scriptPubKey);
        coinbaseTxns.push_back(b.vtx[0]);
    }
}

//
// Create a new brick with just given transactions, coinbase paying to
// scriptPubKey, and try to add it to the current wall.
//
CBrick
TestWall100Setup::CreateAndProcessBrick(const std::vector<CMutableTransaction>& txns, const CScript& scriptPubKey)
{
    const CWallParams& wallparams = Params();
    CBrickTemplate *pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey);
    CBrick& brick = pbricktemplate->brick;

    // Replace mempool-selected txns with just coinbase plus passed-in txns:
    brick.vtx.resize(1);
    BOOST_FOREACH(const CMutableTransaction& tx, txns)
        brick.vtx.push_back(tx);
    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    unsigned int extraNonce = 0;
    IncrementExtraNonce(&brick, wallActive.Tip(), extraNonce);

    while (!CheckProofOfWork(brick.GetPoWHash(), brick.nBits, wallparams.GetConsensus())) ++brick.nNonce;

    CValidationState state;
    ProcessNewBrick(state, wallparams, NULL, &brick, true, NULL, false);

    CBrick result = brick;
    delete pbricktemplate;
    return result;
}

TestWall100Setup::~TestWall100Setup()
{
}


CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(CMutableTransaction &tx, CTxMemPool *pool) {
    CTransaction txn(tx);
    return FromTx(txn, pool);
}

CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(CTransaction &txn, CTxMemPool *pool) {
    bool hasNoDependencies = pool ? pool->HasNoInputsOf(txn) : hadNoDependencies;
    // Hack to assume either its completely dependent on other mempool txs or not at all
    CAmount inWallValue = hasNoDependencies ? txn.GetValueOut() : 0;

    return CTxMemPoolEntry(txn, nFee, nTime, dPriority, nHeight,
                           hasNoDependencies, inWallValue, spendsCoinbase, sigOpCost, lp);
}

void Shutdown(void* parg)
{
  exit(0);
}

void StartShutdown()
{
  exit(0);
}

bool ShutdownRequested()
{
  return false;
}
