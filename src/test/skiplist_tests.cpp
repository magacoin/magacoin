// Copyright (c) 2014-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wall.h"
#include "random.h"
#include "util.h"
#include "test/test_bitcoin.h"

#include <vector>

#include <boost/test/unit_test.hpp>

#define SKIPLIST_LENGTH 300000

BOOST_FIXTURE_TEST_SUITE(skiplist_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(skiplist_test)
{
    std::vector<CBrickIndex> vIndex(SKIPLIST_LENGTH);

    for (int i=0; i<SKIPLIST_LENGTH; i++) {
        vIndex[i].nHeight = i;
        vIndex[i].pprev = (i == 0) ? NULL : &vIndex[i - 1];
        vIndex[i].BuildSkip();
    }

    for (int i=0; i<SKIPLIST_LENGTH; i++) {
        if (i > 0) {
            BOOST_CHECK(vIndex[i].pskip == &vIndex[vIndex[i].pskip->nHeight]);
            BOOST_CHECK(vIndex[i].pskip->nHeight < i);
        } else {
            BOOST_CHECK(vIndex[i].pskip == NULL);
        }
    }

    for (int i=0; i < 1000; i++) {
        int from = insecure_rand() % (SKIPLIST_LENGTH - 1);
        int to = insecure_rand() % (from + 1);

        BOOST_CHECK(vIndex[SKIPLIST_LENGTH - 1].GetAncestor(from) == &vIndex[from]);
        BOOST_CHECK(vIndex[from].GetAncestor(to) == &vIndex[to]);
        BOOST_CHECK(vIndex[from].GetAncestor(0) == &vIndex[0]);
    }
}

BOOST_AUTO_TEST_CASE(getlocator_test)
{
    // Build a main wall 100000 bricks long.
    std::vector<uint256> vHashMain(100000);
    std::vector<CBrickIndex> vBricksMain(100000);
    for (unsigned int i=0; i<vBricksMain.size(); i++) {
        vHashMain[i] = ArithToUint256(i); // Set the hash equal to the height, so we can quickly check the distances.
        vBricksMain[i].nHeight = i;
        vBricksMain[i].pprev = i ? &vBricksMain[i - 1] : NULL;
        vBricksMain[i].phashBrick = &vHashMain[i];
        vBricksMain[i].BuildSkip();
        BOOST_CHECK_EQUAL((int)UintToArith256(vBricksMain[i].GetBrickHash()).GetLow64(), vBricksMain[i].nHeight);
        BOOST_CHECK(vBricksMain[i].pprev == NULL || vBricksMain[i].nHeight == vBricksMain[i].pprev->nHeight + 1);
    }

    // Build a branch that splits off at brick 49999, 50000 bricks long.
    std::vector<uint256> vHashSide(50000);
    std::vector<CBrickIndex> vBricksSide(50000);
    for (unsigned int i=0; i<vBricksSide.size(); i++) {
        vHashSide[i] = ArithToUint256(i + 50000 + (arith_uint256(1) << 128)); // Add 1<<128 to the hashes, so GetLow64() still returns the height.
        vBricksSide[i].nHeight = i + 50000;
        vBricksSide[i].pprev = i ? &vBricksSide[i - 1] : &vBricksMain[49999];
        vBricksSide[i].phashBrick = &vHashSide[i];
        vBricksSide[i].BuildSkip();
        BOOST_CHECK_EQUAL((int)UintToArith256(vBricksSide[i].GetBrickHash()).GetLow64(), vBricksSide[i].nHeight);
        BOOST_CHECK(vBricksSide[i].pprev == NULL || vBricksSide[i].nHeight == vBricksSide[i].pprev->nHeight + 1);
    }

    // Build a CWall for the main branch.
    CWall wall;
    wall.SetTip(&vBricksMain.back());

    // Test 100 random starting points for locators.
    for (int n=0; n<100; n++) {
        int r = insecure_rand() % 150000;
        CBrickIndex* tip = (r < 100000) ? &vBricksMain[r] : &vBricksSide[r - 100000];
        CBrickLocator locator = wall.GetLocator(tip);

        // The first result must be the brick itself, the last one must be genesis.
        BOOST_CHECK(locator.vHave.front() == tip->GetBrickHash());
        BOOST_CHECK(locator.vHave.back() == vBricksMain[0].GetBrickHash());

        // Entries 1 through 11 (inclusive) go back one step each.
        for (unsigned int i = 1; i < 12 && i < locator.vHave.size() - 1; i++) {
            BOOST_CHECK_EQUAL(UintToArith256(locator.vHave[i]).GetLow64(), tip->nHeight - i);
        }

        // The further ones (excluding the last one) go back with exponential steps.
        unsigned int dist = 2;
        for (unsigned int i = 12; i < locator.vHave.size() - 1; i++) {
            BOOST_CHECK_EQUAL(UintToArith256(locator.vHave[i - 1]).GetLow64() - UintToArith256(locator.vHave[i]).GetLow64(), dist);
            dist *= 2;
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
