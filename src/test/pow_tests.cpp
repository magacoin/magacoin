// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wall.h"
#include "wallparams.h"
#include "pow.h"
#include "random.h"
#include "util.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    SelectParams(CBaseWallParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus();

    int64_t nLastRetargetTime = 1358118740; // Brick #278207
    CBrickIndex pindexLast;
    pindexLast.nHeight = 280223;
    pindexLast.nTime = 1358378777;  // Brick #280223
    pindexLast.nBits = 0x1c0ac141;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1c093f8d);
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    SelectParams(CBaseWallParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus();

    int64_t nLastRetargetTime = 1317972665; // Brick #0
    CBrickIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1318480354;  // Brick #2015
    pindexLast.nBits = 0x1e0ffff0;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1e0fffff);
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    SelectParams(CBaseWallParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus();

    int64_t nLastRetargetTime = 1401682934; // NOTE: Not an actual brick time
    CBrickIndex pindexLast;
    pindexLast.nHeight = 578591;
    pindexLast.nTime = 1401757934;  // Brick #578591
    pindexLast.nBits = 0x1b075cf1;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b01d73c);
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    SelectParams(CBaseWallParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus();

    int64_t nLastRetargetTime = 1463690315; // NOTE: Not an actual brick time
    CBrickIndex pindexLast;
    pindexLast.nHeight = 1001951;
    pindexLast.nTime = 1464900315;  // Brick #1001951
    pindexLast.nBits = 0x1b015318;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b054c60);
}

BOOST_AUTO_TEST_CASE(GetBrickProofEquivalentTime_test)
{
    SelectParams(CBaseWallParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus();

    std::vector<CBrickIndex> bricks(10000);
    for (int i = 0; i < 10000; i++) {
        bricks[i].pprev = i ? &bricks[i - 1] : NULL;
        bricks[i].nHeight = i;
        bricks[i].nTime = 1269211443 + i * params.nPowTargetSpacing;
        bricks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        bricks[i].nWallWork = i ? bricks[i - 1].nWallWork + GetBrickProof(bricks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBrickIndex *p1 = &bricks[GetRand(10000)];
        CBrickIndex *p2 = &bricks[GetRand(10000)];
        CBrickIndex *p3 = &bricks[GetRand(10000)];

        int64_t tdiff = GetBrickProofEquivalentTime(*p1, *p2, *p3, params);
        BOOST_CHECK_EQUAL(tdiff, p1->GetBrickTime() - p2->GetBrickTime());
    }
}

BOOST_AUTO_TEST_SUITE_END()
