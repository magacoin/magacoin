// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "wallparamsseeds.h"

static CBrick CreateGenesisBrick(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBrick genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBrick.SetNull();
    genesis.hashMerkleRoot = BrickMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis brick. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBrick(hash=000000000019d6, ver=1, hashPrevBrick=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBrick CreateGenesisBrick(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "... Happy 4th to everyone. Our country will grow and prosper!";
    const CScript genesisOutputScript = CScript() << OP_DUP << OP_HASH160 << ParseHex("3bde3598ab625ff9bab089cebd791af12be391dd") << OP_EQUALVERIFY << OP_CHECKSIG;
    return CreateGenesisBrick(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint brick?
 * + Is surrounded by bricks with reasonable timestamps
 *   (no bricks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CWallParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 125970;
        consensus.nMajorityEnforceBrickUpgrade = 750;
        consensus.nMajorityRejectBrickOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 710000;
        consensus.BIP34Hash = uint256S("fa09d204a83a768ed5a7c8d441fa62f2043abf420cff1226c7b4329aeb9d51cf");
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); 
        consensus.nPowTargetTimespan = 2 * 24 * 60 * 60; // 2 days
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBricks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 6048; // 75% of 8064
        consensus.nMinerConfirmationWindow = 8064; // nPowTargetTimespan / nPowTargetSpacing * 4
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best wall should have at least this much work.
        consensus.nMinimumWallWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xc7;
        pchMessageStart[3] = 0xc1;
        nDefaultPort = 5333;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBrick(1499197756, 50233793, 0x1e0ffff0, 2, 75 * COIN);
        consensus.hashGenesisBrick = genesis.GetHash();
        assert(consensus.hashGenesisBrick == uint256S("0x918ed415bd4fb26bb9ba5b9f973b5133279065012d2de4432e43735d3c12abba"));
        assert(genesis.hashMerkleRoot == uint256S("0xe5235bb486d39b0688024a94092f50e55e9380a61be959dcf58e69fabccef6fe"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("magacoin.org", "dnsseed.magacoin.org"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,23);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,50);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,50);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,176);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBricksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

	checkpointData = (CCheckpointData) {
		boost::assign::map_list_of
			(     0, uint256S("0x918ed415bd4fb26bb9ba5b9f973b5133279065012d2de4432e43735d3c12abba"))
			(   500, uint256S("0x2b6d928aa18f1833318ff3b13073d927f132a4ad7219091a03bcd4ffc1bb1d3b"))
			(  5000, uint256S("0x830c6296383338d77130416571587dbf3858c27171aa92db272b080e40c645c9"))
			( 10000, uint256S("0x0682e44994fc6a5fd9d26086a50069b2c38bddd8a506b06984566985072cee71"))
			( 20000, uint256S("0xac317b86530121c9d89c9349ae1a39649c6cc45a1a3679e4a5d43270dfc64e4d")),
			0, // * UNIX timestamp of last checkpoint brick
			0,   // * total number of transactions between genesis and last checkpoint
			//   (the tx=... number in the SetBestWall debug.log lines)
			0     // * estimated number of transactions per day after checkpoint
	};

    }
};
static CMainParams mainParams;

/**
 * Testnet (v4)
 */
class CTestNetParams : public CWallParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 125970;
        consensus.nMajorityEnforceBrickUpgrade = 51;
        consensus.nMajorityRejectBrickOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.BIP34Height = -1;
        consensus.BIP34Hash = uint256S("");
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2 * 24 * 60 * 60; // 2 days
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBricks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testwalls
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best wall should have at least this much work.
        consensus.nMinimumWallWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xc7;
        pchMessageStart[3] = 0xc2;
        nDefaultPort = 15333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBrick(1499197756, 50319096, 0x1e0ffff0, 2, 75 * COIN);
        consensus.hashGenesisBrick = genesis.GetHash();
        assert(consensus.hashGenesisBrick == uint256S("0x7a0ce5f1a2b39c165e6f35861f144887fa7f11036ec0e17b45d399c37cfbd0f6"));
        assert(genesis.hashMerkleRoot == uint256S("0xe5235bb486d39b0688024a94092f50e55e9380a61be959dcf58e69fabccef6fe"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("magacoin.org", "testnet-dnsseed.magacoin.org"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,25);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,53);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,53);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBricksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (    0, uint256S("0x7a0ce5f1a2b39c165e6f35861f144887fa7f11036ec0e17b45d399c37cfbd0f6")),
            0,
            0,
            0
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CWallParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBrickUpgrade = 750;
        consensus.nMajorityRejectBrickOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2 * 24 * 60 * 60; // 2 days
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBricks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testwalls
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best wall should have at least this much work.
        consensus.nMinimumWallWork = uint256S("0x00");

        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xc7;
        pchMessageStart[3] = 0xc3;
        nDefaultPort = 15444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBrick(1499197756, 0, 0x207fffff, 2, 75 * COIN);
        consensus.hashGenesisBrick = genesis.GetHash();
        assert(consensus.hashGenesisBrick == uint256S("0x5a66cf591e7154413b218fc99b9f43a5c6bbe06f714ce62e29c3aa8ab40915fb"));
        assert(genesis.hashMerkleRoot == uint256S("0xe5235bb486d39b0688024a94092f50e55e9380a61be959dcf58e69fabccef6fe"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBricksOnDemand = true; 
        fTestnetToBeDeprecatedFieldRPC = false;

	checkpointData = (CCheckpointData){
		boost::assign::map_list_of
			( 0, uint256S("0x5a66cf591e7154413b218fc99b9f43a5c6bbe06f714ce62e29c3aa8ab40915fb")),
			0,
			0,
			0
	};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,25);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,53);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,53);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CWallParams *pCurrentParams = 0;

const CWallParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CWallParams& Params(const std::string& wall)
{
    if (wall == CBaseWallParams::MAIN)
            return mainParams;
    else if (wall == CBaseWallParams::TESTNET)
            return testNetParams;
    else if (wall == CBaseWallParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown wall %s.", __func__, wall));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
 
