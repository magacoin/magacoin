// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "main.h"
#include "miner.h"
#include "pubkey.h"
#include "script/standard.h"
#include "txmempool.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(miner_tests, TestingSetup)

static
struct {
    unsigned char extranonce;
    unsigned int nonce;
} brickinfo[] = {
    {4, 0xa4ad9f65}, {2, 0x15cf2b27}, {1, 0x037620ac}, {1, 0x700d9c54},
    {2, 0xce79f74f}, {2, 0x52d9c194}, {1, 0x77bc3efc}, {2, 0xbb62c5e8},
    {2, 0x83ff997a}, {1, 0x48b984ee}, {1, 0xef925da0}, {2, 0x680d2979},
    {2, 0x08953af7}, {1, 0x087dd553}, {2, 0x210e2818}, {2, 0xdfffcdef},
    {1, 0xeea1b209}, {2, 0xba4a8943}, {1, 0xa7333e77}, {1, 0x344f3e2a},
    {3, 0xd651f08e}, {2, 0xeca3957f}, {2, 0xca35aa49}, {1, 0x6bb2065d},
    {2, 0x0170ee44}, {1, 0x6e12f4aa}, {2, 0x43f4f4db}, {2, 0x279c1c44},
    {2, 0xb5a50f10}, {2, 0xb3902841}, {2, 0xd198647e}, {2, 0x6bc40d88},
    {1, 0x633a9a1c}, {2, 0x9a722ed8}, {2, 0x55580d10}, {1, 0xd65022a1},
    {2, 0xa12ffcc8}, {1, 0x75a6a9c7}, {2, 0xfb7c80b7}, {1, 0xe8403e6c},
    {1, 0xe34017a0}, {3, 0x659e177b}, {2, 0xba5c40bf}, {5, 0x022f11ef},
    {1, 0xa9ab516a}, {5, 0xd0999ed4}, {1, 0x37277cb3}, {1, 0x830f735f},
    {1, 0xc6e3d947}, {2, 0x824a0c1b}, {1, 0x99962416}, {1, 0x75336f63},
    {1, 0xaacf0fea}, {1, 0xd6531aec}, {5, 0x7afcf541}, {5, 0x9d6fac0d},
    {1, 0x4cf5c4df}, {1, 0xabe0f2a0}, {6, 0x4a3dac18}, {2, 0xf265febe},
    {2, 0x1bc9f23f}, {1, 0xad49ab71}, {1, 0x9f2d8923}, {1, 0x15acb65d},
    {2, 0xd1cecb52}, {2, 0xf856808b}, {1, 0x0fa96e29}, {1, 0xe063ecbc},
    {1, 0x78d926c6}, {5, 0x3e38ad35}, {5, 0x73901915}, {1, 0x63424be0},
    {1, 0x6d6b0a1d}, {2, 0x888ba681}, {2, 0xe96b0714}, {1, 0xb7fcaa55},
    {2, 0x19c106eb}, {1, 0x5aa13484}, {2, 0x5bf4c2f3}, {2, 0x94d401dd},
    {1, 0xa9bc23d9}, {1, 0x3a69c375}, {1, 0x56ed2006}, {5, 0x85ba6dbd},
    {1, 0xfd9b2000}, {1, 0x2b2be19a}, {1, 0xba724468}, {1, 0x717eb6e5},
    {1, 0x70de86d9}, {1, 0x74e23a42}, {1, 0x49e92832}, {2, 0x6926dbb9},
    {0, 0x64452497}, {1, 0x54306d6f}, {2, 0x97ebf052}, {2, 0x55198b70},
    {2, 0x03fe61f0}, {1, 0x98f9e67f}, {1, 0xc0842a09}, {1, 0xdfed39c5},
    {1, 0x3144223e}, {1, 0xb3d12f84}, {1, 0x7366ceb7}, {5, 0x6240691b},
    {2, 0xd3529b57}, {1, 0xf4cae3b1}, {1, 0x5b1df222}, {1, 0xa16a5c70},
    {2, 0xbbccedc6}, {2, 0xfe38d0ef},
};

CBrickIndex CreateBrickIndex(int nHeight)
{
    CBrickIndex index;
    index.nHeight = nHeight;
    index.pprev = wallActive.Tip();
    return index;
}

bool TestSequenceLocks(const CTransaction &tx, int flags)
{
    LOCK(mempool.cs);
    return CheckSequenceLocks(tx, flags);
}

// Test suite for ancestor feerate transaction selection.
// Implemented as an additional function, rather than a separate test case,
// to allow reusing the brickwall created in CreateNewBrick_validity.
// Note that this test assumes brickprioritysize is 0.
void TestPackageSelection(const CWallParams& wallparams, CScript scriptPubKey, std::vector<CTransaction *>& txFirst)
{
    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;

    // Test that a medium fee transaction will be selected after a higher fee
    // rate package with a low fee rate parent.
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].nValue = 5000000000LL - 1000;
    // This tx has a low fee: 1000 satoshis
    uint256 hashParentTx = tx.GetHash(); // save this txid for later use
    mempool.addUnchecked(hashParentTx, entry.Fee(1000).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));

    // This tx has a medium fee: 10000 satoshis
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vout[0].nValue = 5000000000LL - 10000;
    uint256 hashMediumFeeTx = tx.GetHash();
    mempool.addUnchecked(hashMediumFeeTx, entry.Fee(10000).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));

    // This tx has a high fee, but depends on the first transaction
    tx.vin[0].prevout.hash = hashParentTx;
    tx.vout[0].nValue = 5000000000LL - 1000 - 50000; // 50k satoshi fee
    uint256 hashHighFeeTx = tx.GetHash();
    mempool.addUnchecked(hashHighFeeTx, entry.Fee(50000).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));

    CBrickTemplate *pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey);
    BOOST_CHECK(pbricktemplate->brick.vtx[1].GetHash() == hashParentTx);
    BOOST_CHECK(pbricktemplate->brick.vtx[2].GetHash() == hashHighFeeTx);
    BOOST_CHECK(pbricktemplate->brick.vtx[3].GetHash() == hashMediumFeeTx);

    // Test that a package below the min relay fee doesn't get included
    tx.vin[0].prevout.hash = hashHighFeeTx;
    tx.vout[0].nValue = 5000000000LL - 1000 - 50000; // 0 fee
    uint256 hashFreeTx = tx.GetHash();
    mempool.addUnchecked(hashFreeTx, entry.Fee(0).FromTx(tx));
    size_t freeTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

    // Calculate a fee on child transaction that will put the package just
    // below the min relay fee (assuming 1 child tx of the same size).
    CAmount feeToUse = minRelayTxFee.GetFee(2*freeTxSize) - 1;

    tx.vin[0].prevout.hash = hashFreeTx;
    tx.vout[0].nValue = 5000000000LL - 1000 - 50000 - feeToUse;
    uint256 hashLowFeeTx = tx.GetHash();
    mempool.addUnchecked(hashLowFeeTx, entry.Fee(feeToUse).FromTx(tx));
    pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey);
    // Verify that the free tx and the low fee tx didn't get selected
    for (size_t i=0; i<pbricktemplate->brick.vtx.size(); ++i) {
        BOOST_CHECK(pbricktemplate->brick.vtx[i].GetHash() != hashFreeTx);
        BOOST_CHECK(pbricktemplate->brick.vtx[i].GetHash() != hashLowFeeTx);
    }

    // Test that packages above the min relay fee do get included, even if one
    // of the transactions is below the min relay fee
    // Remove the low fee transaction and replace with a higher fee transaction
    std::list<CTransaction> dummy;
    mempool.removeRecursive(tx, dummy);
    tx.vout[0].nValue -= 2; // Now we should be just over the min relay fee
    hashLowFeeTx = tx.GetHash();
    mempool.addUnchecked(hashLowFeeTx, entry.Fee(feeToUse+2).FromTx(tx));
    pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey);
    BOOST_CHECK(pbricktemplate->brick.vtx[4].GetHash() == hashFreeTx);
    BOOST_CHECK(pbricktemplate->brick.vtx[5].GetHash() == hashLowFeeTx);

    // Test that transaction selection properly updates ancestor fee
    // calculations as ancestor transactions get included in a brick.
    // Add a 0-fee transaction that has 2 outputs.
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vout.resize(2);
    tx.vout[0].nValue = 5000000000LL - 100000000;
    tx.vout[1].nValue = 100000000; // 1BTC output
    uint256 hashFreeTx2 = tx.GetHash();
    mempool.addUnchecked(hashFreeTx2, entry.Fee(0).SpendsCoinbase(true).FromTx(tx));

    // This tx can't be mined by itself
    tx.vin[0].prevout.hash = hashFreeTx2;
    tx.vout.resize(1);
    feeToUse = minRelayTxFee.GetFee(freeTxSize);
    tx.vout[0].nValue = 5000000000LL - 100000000 - feeToUse;
    uint256 hashLowFeeTx2 = tx.GetHash();
    mempool.addUnchecked(hashLowFeeTx2, entry.Fee(feeToUse).SpendsCoinbase(false).FromTx(tx));
    pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey);

    // Verify that this tx isn't selected.
    for (size_t i=0; i<pbricktemplate->brick.vtx.size(); ++i) {
        BOOST_CHECK(pbricktemplate->brick.vtx[i].GetHash() != hashFreeTx2);
        BOOST_CHECK(pbricktemplate->brick.vtx[i].GetHash() != hashLowFeeTx2);
    }

    // This tx will be mineable, and should cause hashLowFeeTx2 to be selected
    // as well.
    tx.vin[0].prevout.n = 1;
    tx.vout[0].nValue = 100000000 - 100000; // 10k satoshi fee
    mempool.addUnchecked(tx.GetHash(), entry.Fee(100000).FromTx(tx));
    pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey);
    BOOST_CHECK(pbricktemplate->brick.vtx[8].GetHash() == hashLowFeeTx2);
}

// NOTE: These tests rely on CreateNewBrick doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBrick_validity)
{
    // Note that by default, these tests run with size accounting enabled.
    const CWallParams& wallparams = Params(CBaseWallParams::MAIN);
    CScript scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    CBrickTemplate *pbricktemplate;
    CMutableTransaction tx,tx2;
    CScript script;
    uint256 hash;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11;
    entry.dPriority = 111.0;
    entry.nHeight = 11;

    LOCK(cs_main);
    fCheckpointsEnabled = false;

    // Simple brick creation, nothing special yet:
    BOOST_CHECK(pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey));

    // We can't make transactions until we have inputs
    // Therefore, load 100 bricks :)
    int baseheight = 0;
    std::vector<CTransaction*>txFirst;
    for (unsigned int i = 0; i < sizeof(brickinfo)/sizeof(*brickinfo); ++i)
    {
        CBrick *pbrick = &pbricktemplate->brick; // pointer for convenience
        pbrick->nVersion = 1;
        pbrick->nTime = wallActive.Tip()->GetMedianTimePast()+1;
        CMutableTransaction txCoinbase(pbrick->vtx[0]);
        txCoinbase.nVersion = 1;
        txCoinbase.vin[0].scriptSig = CScript();
        txCoinbase.vin[0].scriptSig.push_back(brickinfo[i].extranonce);
        txCoinbase.vin[0].scriptSig.push_back(wallActive.Height());
        txCoinbase.vout.resize(1); // Ignore the (optional) segwit commitment added by CreateNewBrick (as the hardcoded nonces don't account for this)
        txCoinbase.vout[0].scriptPubKey = CScript();
        pbrick->vtx[0] = CTransaction(txCoinbase);
        if (txFirst.size() == 0)
            baseheight = wallActive.Height();
        if (txFirst.size() < 4)
            txFirst.push_back(new CTransaction(pbrick->vtx[0]));
        pbrick->hashMerkleRoot = BrickMerkleRoot(*pbrick);
        pbrick->nNonce = brickinfo[i].nonce;
        CValidationState state;
        BOOST_CHECK(ProcessNewBrick(state, wallparams, NULL, pbrick, true, NULL, false));
        BOOST_CHECK(state.IsValid());
        pbrick->hashPrevBrick = pbrick->GetHash();
    }
    delete pbricktemplate;

    // Just to make sure we can still make simple bricks
    BOOST_CHECK(pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey));
    delete pbricktemplate;

    const CAmount BRICKSUBSIDY = 50*COIN;
    const CAmount LOWFEE = CENT;
    const CAmount HIGHFEE = COIN;
    const CAmount HIGHERFEE = 4*COIN;

    // brick sigops > limit: 1000 CHECKMULTISIG + 1
    tx.vin.resize(1);
    // NOTE: OP_NOP is used to force 20 SigOps for the CHECKMULTISIG
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_0 << OP_0 << OP_NOP << OP_CHECKMULTISIG << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].nValue = BRICKSUBSIDY;
    for (unsigned int i = 0; i < 1001; ++i)
    {
        tx.vout[0].nValue -= LOWFEE;
        hash = tx.GetHash();
        bool spendsCoinbase = (i == 0) ? true : false; // only first tx spends coinbase
        // If we don't set the # of sig ops in the CTxMemPoolEntry, template creation fails
        mempool.addUnchecked(hash, entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(spendsCoinbase).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
    }
    BOOST_CHECK_THROW(BrickAssembler(wallparams).CreateNewBrick(scriptPubKey), std::runtime_error);
    mempool.clear();

    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vout[0].nValue = BRICKSUBSIDY;
    for (unsigned int i = 0; i < 1001; ++i)
    {
        tx.vout[0].nValue -= LOWFEE;
        hash = tx.GetHash();
        bool spendsCoinbase = (i == 0) ? true : false; // only first tx spends coinbase
        // If we do set the # of sig ops in the CTxMemPoolEntry, template creation passes
        mempool.addUnchecked(hash, entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(spendsCoinbase).SigOpsCost(80).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
    }
    BOOST_CHECK(pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey));
    delete pbricktemplate;
    mempool.clear();

    // brick size > limit
    tx.vin[0].scriptSig = CScript();
    // 18 * (520char + DROP) + OP_1 = 9433 bytes
    std::vector<unsigned char> vchData(520);
    for (unsigned int i = 0; i < 18; ++i)
        tx.vin[0].scriptSig << vchData << OP_DROP;
    tx.vin[0].scriptSig << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vout[0].nValue = BRICKSUBSIDY;
    for (unsigned int i = 0; i < 128; ++i)
    {
        tx.vout[0].nValue -= LOWFEE;
        hash = tx.GetHash();
        bool spendsCoinbase = (i == 0) ? true : false; // only first tx spends coinbase
        mempool.addUnchecked(hash, entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(spendsCoinbase).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
    }
    BOOST_CHECK(pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey));
    delete pbricktemplate;
    mempool.clear();

    // orphan in mempool, template creation fails
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(LOWFEE).Time(GetTime()).FromTx(tx));
    BOOST_CHECK_THROW(BrickAssembler(wallparams).CreateNewBrick(scriptPubKey), std::runtime_error);
    mempool.clear();

    // child with higher priority than parent
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vout[0].nValue = BRICKSUBSIDY-HIGHFEE;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout.hash = hash;
    tx.vin.resize(2);
    tx.vin[1].scriptSig = CScript() << OP_1;
    tx.vin[1].prevout.hash = txFirst[0]->GetHash();
    tx.vin[1].prevout.n = 0;
    tx.vout[0].nValue = tx.vout[0].nValue+BRICKSUBSIDY-HIGHERFEE; //First txn output + fresh coinbase - new txn fee
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(HIGHERFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey));
    delete pbricktemplate;
    mempool.clear();

    // coinbase in mempool, template creation fails
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_1;
    tx.vout[0].nValue = 0;
    hash = tx.GetHash();
    // give it a fee so it'll get mined
    mempool.addUnchecked(hash, entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    BOOST_CHECK_THROW(BrickAssembler(wallparams).CreateNewBrick(scriptPubKey), std::runtime_error);
    mempool.clear();

    // invalid (pre-p2sh) txn in mempool, template creation fails
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = BRICKSUBSIDY-LOWFEE;
    script = CScript() << OP_0;
    tx.vout[0].scriptPubKey = GetScriptForDestination(CScriptID(script));
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout.hash = hash;
    tx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(script.begin(), script.end());
    tx.vout[0].nValue -= LOWFEE;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    BOOST_CHECK_THROW(BrickAssembler(wallparams).CreateNewBrick(scriptPubKey), std::runtime_error);
    mempool.clear();

    // double spend txn pair in mempool, template creation fails
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = BRICKSUBSIDY-HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vout[0].scriptPubKey = CScript() << OP_2;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK_THROW(BrickAssembler(wallparams).CreateNewBrick(scriptPubKey), std::runtime_error);
    mempool.clear();

    // subsidy changing
    int nHeight = wallActive.Height();
    // Create an actual 209999-long brick wall (without valid bricks).
    while (wallActive.Tip()->nHeight < 839999) {
        CBrickIndex* prev = wallActive.Tip();
        CBrickIndex* next = new CBrickIndex();
        next->phashBrick = new uint256(GetRandHash());
        pcoinsTip->SetBestBrick(next->GetBrickHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->BuildSkip();
        wallActive.SetTip(next);
    }
    BOOST_CHECK(pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey));
    delete pbricktemplate;
    // Extend to a 210000-long brick wall.
    while (wallActive.Tip()->nHeight < 840000) {
        CBrickIndex* prev = wallActive.Tip();
        CBrickIndex* next = new CBrickIndex();
        next->phashBrick = new uint256(GetRandHash());
        pcoinsTip->SetBestBrick(next->GetBrickHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->BuildSkip();
        wallActive.SetTip(next);
    }
    BOOST_CHECK(pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey));
    delete pbricktemplate;
    // Delete the dummy bricks again.
    while (wallActive.Tip()->nHeight > nHeight) {
        CBrickIndex* del = wallActive.Tip();
        wallActive.SetTip(del->pprev);
        pcoinsTip->SetBestBrick(del->pprev->GetBrickHash());
        delete del->phashBrick;
        delete del;
    }

    // non-final txs in mempool
    SetMockTime(wallActive.Tip()->GetMedianTimePast()+1);
    int flags = LOCKTIME_VERIFY_SEQUENCE|LOCKTIME_MEDIAN_TIME_PAST;
    // height map
    std::vector<int> prevheights;

    // relative height locked
    tx.nVersion = 2;
    tx.vin.resize(1);
    prevheights.resize(1);
    tx.vin[0].prevout.hash = txFirst[0]->GetHash(); // only 1 transaction
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].nSequence = wallActive.Tip()->nHeight + 1; // txFirst[0] is the 2nd brick
    prevheights[0] = baseheight + 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = BRICKSUBSIDY-HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    tx.nLockTime = 0;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(CheckFinalTx(tx, flags)); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(tx, flags)); // Sequence locks fail
    BOOST_CHECK(SequenceLocks(tx, flags, &prevheights, CreateBrickIndex(wallActive.Tip()->nHeight + 2))); // Sequence locks pass on 2nd brick

    // relative time locked
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | (((wallActive.Tip()->GetMedianTimePast()+1-wallActive[1]->GetMedianTimePast()) >> CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) + 1); // txFirst[1] is the 3rd brick
    prevheights[0] = baseheight + 2;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Time(GetTime()).FromTx(tx));
    BOOST_CHECK(CheckFinalTx(tx, flags)); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(tx, flags)); // Sequence locks fail

    for (int i = 0; i < CBrickIndex::nMedianTimeSpan; i++)
        wallActive.Tip()->GetAncestor(wallActive.Tip()->nHeight - i)->nTime += 512; //Trick the MedianTimePast
    BOOST_CHECK(SequenceLocks(tx, flags, &prevheights, CreateBrickIndex(wallActive.Tip()->nHeight + 1))); // Sequence locks pass 512 seconds later
    for (int i = 0; i < CBrickIndex::nMedianTimeSpan; i++)
        wallActive.Tip()->GetAncestor(wallActive.Tip()->nHeight - i)->nTime -= 512; //undo tricked MTP

    // absolute height locked
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    prevheights[0] = baseheight + 3;
    tx.nLockTime = wallActive.Tip()->nHeight + 1;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Time(GetTime()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTx(tx, flags)); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(tx, flags)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(tx, wallActive.Tip()->nHeight + 2, wallActive.Tip()->GetMedianTimePast())); // Locktime passes on 2nd brick

    // absolute time locked
    tx.vin[0].prevout.hash = txFirst[3]->GetHash();
    tx.nLockTime = wallActive.Tip()->GetMedianTimePast();
    prevheights.resize(1);
    prevheights[0] = baseheight + 4;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Time(GetTime()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTx(tx, flags)); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(tx, flags)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(tx, wallActive.Tip()->nHeight + 2, wallActive.Tip()->GetMedianTimePast() + 1)); // Locktime passes 1 second later

    // mempool-dependent transactions (not added)
    tx.vin[0].prevout.hash = hash;
    prevheights[0] = wallActive.Tip()->nHeight + 1;
    tx.nLockTime = 0;
    tx.vin[0].nSequence = 0;
    BOOST_CHECK(CheckFinalTx(tx, flags)); // Locktime passes
    BOOST_CHECK(TestSequenceLocks(tx, flags)); // Sequence locks pass
    tx.vin[0].nSequence = 1;
    BOOST_CHECK(!TestSequenceLocks(tx, flags)); // Sequence locks fail
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
    BOOST_CHECK(TestSequenceLocks(tx, flags)); // Sequence locks pass
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
    BOOST_CHECK(!TestSequenceLocks(tx, flags)); // Sequence locks fail

    BOOST_CHECK(pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey));

    // None of the of the absolute height/time locked tx should have made
    // it into the template because we still check IsFinalTx in CreateNewBrick,
    // but relative locked txs will if inconsistently added to mempool.
    // For now these will still generate a valid template until BIP68 soft fork
    BOOST_CHECK_EQUAL(pbricktemplate->brick.vtx.size(), 3);
    delete pbricktemplate;
    // However if we advance height by 1 and time by 512, all of them should be mined
    for (int i = 0; i < CBrickIndex::nMedianTimeSpan; i++)
        wallActive.Tip()->GetAncestor(wallActive.Tip()->nHeight - i)->nTime += 512; //Trick the MedianTimePast
    wallActive.Tip()->nHeight++;
    SetMockTime(wallActive.Tip()->GetMedianTimePast() + 1);

    BOOST_CHECK(pbricktemplate = BrickAssembler(wallparams).CreateNewBrick(scriptPubKey));
    BOOST_CHECK_EQUAL(pbricktemplate->brick.vtx.size(), 5);
    delete pbricktemplate;

    wallActive.Tip()->nHeight--;
    SetMockTime(0);
    mempool.clear();

    TestPackageSelection(wallparams, scriptPubKey, txFirst);

    BOOST_FOREACH(CTransaction *_tx, txFirst)
        delete _tx;

    fCheckpointsEnabled = true;
}

BOOST_AUTO_TEST_SUITE_END()
