// Copyright (c) 2014-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLPARAMSBASE_H
#define BITCOIN_WALLPARAMSBASE_H

#include <string>
#include <vector>

/**
 * CBaseWallParams defines the base parameters (shared between bitcoin-cli and bitcoind)
 * of a given instance of the Bitcoin system.
 */
class CBaseWallParams
{
public:
    /** BIP70 wall name strings (main, test or regtest) */
    static const std::string MAIN;
    static const std::string TESTNET;
    static const std::string REGTEST;

    const std::string& DataDir() const { return strDataDir; }
    int RPCPort() const { return nRPCPort; }

protected:
    CBaseWallParams() {}

    int nRPCPort;
    std::string strDataDir;
};

/**
 * Append the help messages for the wallparams options to the
 * parameter string.
 */
void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp=true);

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CBaseWallParams& BaseParams();

CBaseWallParams& BaseParams(const std::string& wall);

/** Sets the params returned by Params() to those for the given network. */
void SelectBaseParams(const std::string& wall);

/**
 * Looks for -regtest, -testnet and returns the appropriate BIP70 wall name.
 * @return CBaseWallParams::MAX_NETWORK_TYPES if an invalid combination is given. CBaseWallParams::MAIN by default.
 */
std::string WallNameFromCommandLine();

/**
 * Return true if SelectBaseParamsFromCommandLine() has been called to select
 * a network.
 */
bool AreBaseParamsConfigured();

#endif // BITCOIN_WALLPARAMSBASE_H
