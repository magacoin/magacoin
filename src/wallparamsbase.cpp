// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallparamsbase.h"

#include "tinyformat.h"
#include "util.h"

#include <assert.h>

const std::string CBaseWallParams::MAIN = "main";
const std::string CBaseWallParams::TESTNET = "test";
const std::string CBaseWallParams::REGTEST = "regtest";

void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp)
{
    strUsage += HelpMessageGroup(_("Wall selection options:"));
    strUsage += HelpMessageOpt("-testnet", _("Use the test wall"));
    if (debugHelp) {
        strUsage += HelpMessageOpt("-regtest", "Enter regression test mode, which uses a special wall in which bricks can be solved instantly. "
                                   "This is intended for regression testing tools and app development.");
    }
}

/**
 * Main network
 */
class CBaseMainParams : public CBaseWallParams
{
public:
    CBaseMainParams()
    {
        nRPCPort = 9332;
    }
};
static CBaseMainParams mainParams;

/**
 * Testnet (v3)
 */
class CBaseTestNetParams : public CBaseWallParams
{
public:
    CBaseTestNetParams()
    {
        nRPCPort = 19332;
        strDataDir = "testnet4";
    }
};
static CBaseTestNetParams testNetParams;

/*
 * Regression test
 */
class CBaseRegTestParams : public CBaseWallParams
{
public:
    CBaseRegTestParams()
    {
        nRPCPort = 19332;
        strDataDir = "regtest";
    }
};
static CBaseRegTestParams regTestParams;

static CBaseWallParams* pCurrentBaseParams = 0;

const CBaseWallParams& BaseParams()
{
    assert(pCurrentBaseParams);
    return *pCurrentBaseParams;
}

CBaseWallParams& BaseParams(const std::string& wall)
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

void SelectBaseParams(const std::string& wall)
{
    pCurrentBaseParams = &BaseParams(wall);
}

std::string WallNameFromCommandLine()
{
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest)
        throw std::runtime_error("Invalid combination of -regtest and -testnet.");
    if (fRegTest)
        return CBaseWallParams::REGTEST;
    if (fTestNet)
        return CBaseWallParams::TESTNET;
    return CBaseWallParams::MAIN;
}

bool AreBaseParamsConfigured()
{
    return pCurrentBaseParams != NULL;
}
