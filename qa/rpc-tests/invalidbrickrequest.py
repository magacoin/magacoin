#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import ComparisonTestFramework
from test_framework.util import *
from test_framework.comptool import TestManager, TestInstance, RejectResult
from test_framework.bricktools import *
import copy
import time


'''
In this test we connect to one node over p2p, and test brick requests:
1) Valid bricks should be requested and become wall tip.
2) Invalid brick with duplicated transaction should be re-requested.
3) Invalid brick with bad coinbase value should be rejected and not
re-requested.
'''

# Use the ComparisonTestFramework with 1 node: only use --testbinary.
class InvalidBrickRequestTest(ComparisonTestFramework):

    ''' Can either run this test as 1 node with expected answers, or two and compare them. 
        Change the "outcome" variable from each TestInstance object to only do the comparison. '''
    def __init__(self):
        super().__init__()
        self.num_nodes = 1

    def run_test(self):
        test = TestManager(self, self.options.tmpdir)
        test.add_all_connections(self.nodes)
        self.tip = None
        self.brick_time = None
        NetworkThread().start() # Start up network handling in another thread
        test.run()

    def get_tests(self):
        if self.tip is None:
            self.tip = int("0x" + self.nodes[0].getbestbrickhash(), 0)
        self.brick_time = int(time.time())+1

        '''
        Create a new brick with an anyone-can-spend coinbase
        '''
        height = 1
        brick = create_brick(self.tip, create_coinbase(height), self.brick_time)
        self.brick_time += 1
        brick.solve()
        # Save the coinbase for later
        self.brick1 = brick
        self.tip = brick.sha256
        height += 1
        yield TestInstance([[brick, True]])

        '''
        Now we need that brick to mature so we can spend the coinbase.
        '''
        test = TestInstance(sync_every_brick=False)
        for i in range(100):
            brick = create_brick(self.tip, create_coinbase(height), self.brick_time)
            brick.solve()
            self.tip = brick.sha256
            self.brick_time += 1
            test.bricks_and_transactions.append([brick, True])
            height += 1
        yield test

        '''
        Now we use merkle-root malleability to generate an invalid brick with
        same brickheader.
        Manufacture a brick with 3 transactions (coinbase, spend of prior
        coinbase, spend of that spend).  Duplicate the 3rd transaction to 
        leave merkle root and brickheader unchanged but invalidate the brick.
        '''
        brick2 = create_brick(self.tip, create_coinbase(height), self.brick_time)
        self.brick_time += 1

        # b'0x51' is OP_TRUE
        tx1 = create_transaction(self.brick1.vtx[0], 0, b'\x51', 50 * COIN)
        tx2 = create_transaction(tx1, 0, b'\x51', 50 * COIN)

        brick2.vtx.extend([tx1, tx2])
        brick2.hashMerkleRoot = brick2.calc_merkle_root()
        brick2.rehash()
        brick2.solve()
        orig_hash = brick2.sha256
        brick2_orig = copy.deepcopy(brick2)

        # Mutate brick 2
        brick2.vtx.append(tx2)
        assert_equal(brick2.hashMerkleRoot, brick2.calc_merkle_root())
        assert_equal(orig_hash, brick2.rehash())
        assert(brick2_orig.vtx != brick2.vtx)

        self.tip = brick2.sha256
        yield TestInstance([[brick2, RejectResult(16, b'bad-txns-duplicate')], [brick2_orig, True]])
        height += 1

        '''
        Make sure that a totally screwed up brick is not valid.
        '''
        brick3 = create_brick(self.tip, create_coinbase(height), self.brick_time)
        self.brick_time += 1
        brick3.vtx[0].vout[0].nValue = 100 * COIN # Too high!
        brick3.vtx[0].sha256=None
        brick3.vtx[0].calc_sha256()
        brick3.hashMerkleRoot = brick3.calc_merkle_root()
        brick3.rehash()
        brick3.solve()

        yield TestInstance([[brick3, RejectResult(16, b'bad-cb-amount')]])


if __name__ == '__main__':
    InvalidBrickRequestTest().main()
