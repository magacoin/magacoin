// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include "consensus/params.h"

#include <stdint.h>

class CBrickHeader;
class CBrickIndex;
class uint256;

unsigned int GetNextWorkRequired(const CBrickIndex* pindexLast, const CBrickHeader *pbrick, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBrickIndex* pindexLast, int64_t nFirstBrickTime, const Consensus::Params&);

/** Check whether a brick hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);

#endif // BITCOIN_POW_H
