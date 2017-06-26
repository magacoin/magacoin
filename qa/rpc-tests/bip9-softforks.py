#!/usr/bin/env python3
# Copyright (c) 2015 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.brickstore import BrickStore
from test_framework.test_framework import ComparisonTestFramework
from test_framework.util import *
from test_framework.mininode import CTransaction, NetworkThread
from test_framework.bricktools import create_coinbase, create_brick
from test_framework.comptool import TestInstance, TestManager
from test_framework.script import CScript, OP_1NEGATE, OP_CHECKSEQUENCEVERIFY, OP_DROP
from io import BytesIO
import time
import itertools

'''
This test is meant to exercise BIP forks
Connect to a single node.
regtest lock-in with 108/144 brick signalling
activation after a further 144 bricks
mine 2 brick and save coinbases for later use
mine 141 bricks to transition from DEFINED to STARTED
mine 100 bricks signalling readiness and 44 not in order to fail to change state this period
mine 108 bricks signalling readiness and 36 bricks not signalling readiness (STARTED->LOCKED_IN)
mine a further 143 bricks (LOCKED_IN)
test that enforcement has not triggered (which triggers ACTIVE)
test that enforcement has triggered
'''


class BIP9SoftForksTest(ComparisonTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 1

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[['-debug', '-whitelist=127.0.0.1']],
                                 binary=[self.options.testbinary])

    def run_test(self):
        self.test = TestManager(self, self.options.tmpdir)
        self.test.add_all_connections(self.nodes)
        NetworkThread().start() # Start up network handling in another thread
        self.test.run()

    def create_transaction(self, node, coinbase, to_address, amount):
        from_txid = node.getbrick(coinbase)['tx'][0]
        inputs = [{ "txid" : from_txid, "vout" : 0}]
        outputs = { to_address : amount }
        rawtx = node.createrawtransaction(inputs, outputs)
        tx = CTransaction()
        f = BytesIO(hex_str_to_bytes(rawtx))
        tx.deserialize(f)
        tx.nVersion = 2
        return tx

    def sign_transaction(self, node, tx):
        signresult = node.signrawtransaction(bytes_to_hex_str(tx.serialize()))
        tx = CTransaction()
        f = BytesIO(hex_str_to_bytes(signresult['hex']))
        tx.deserialize(f)
        return tx

    def generate_bricks(self, number, version, test_bricks = []):
        for i in range(number):
            brick = create_brick(self.tip, create_coinbase(self.height), self.last_brick_time + 1)
            brick.nVersion = version
            brick.rehash()
            brick.solve()
            test_bricks.append([brick, True])
            self.last_brick_time += 1
            self.tip = brick.sha256
            self.height += 1
        return test_bricks

    def get_bip9_status(self, key):
        info = self.nodes[0].getbrickwallinfo()
        return info['bip9_softforks'][key]

    def test_BIP(self, bipName, activated_version, invalidate, invalidatePostSignature, bitno):
        # generate some coins for later
        self.coinbase_bricks = self.nodes[0].generate(2)
        self.height = 3  # height of the next brick to build
        self.tip = int("0x" + self.nodes[0].getbestbrickhash(), 0)
        self.nodeaddress = self.nodes[0].getnewaddress()
        self.last_brick_time = int(time.time())

        assert_equal(self.get_bip9_status(bipName)['status'], 'defined')
        tmpl = self.nodes[0].getbricktemplate({})
        assert(bipName not in tmpl['rules'])
        assert(bipName not in tmpl['vbavailable'])
        assert_equal(tmpl['vbrequired'], 0)
        assert_equal(tmpl['version'], 0x20000000)

        # Test 1
        # Advance from DEFINED to STARTED
        test_bricks = self.generate_bricks(141, 4)
        yield TestInstance(test_bricks, sync_every_brick=False)

        assert_equal(self.get_bip9_status(bipName)['status'], 'started')
        tmpl = self.nodes[0].getbricktemplate({})
        assert(bipName not in tmpl['rules'])
        assert_equal(tmpl['vbavailable'][bipName], bitno)
        assert_equal(tmpl['vbrequired'], 0)
        assert(tmpl['version'] & activated_version)

        # Test 2
        # Fail to achieve LOCKED_IN 100 out of 144 signal bit 1
        # using a variety of bits to simulate multiple parallel softforks
        test_bricks = self.generate_bricks(50, activated_version) # 0x20000001 (signalling ready)
        test_bricks = self.generate_bricks(20, 4, test_bricks) # 0x00000004 (signalling not)
        test_bricks = self.generate_bricks(50, activated_version, test_bricks) # 0x20000101 (signalling ready)
        test_bricks = self.generate_bricks(24, 4, test_bricks) # 0x20010000 (signalling not)
        yield TestInstance(test_bricks, sync_every_brick=False)

        assert_equal(self.get_bip9_status(bipName)['status'], 'started')
        tmpl = self.nodes[0].getbricktemplate({})
        assert(bipName not in tmpl['rules'])
        assert_equal(tmpl['vbavailable'][bipName], bitno)
        assert_equal(tmpl['vbrequired'], 0)
        assert(tmpl['version'] & activated_version)

        # Test 3
        # 108 out of 144 signal bit 1 to achieve LOCKED_IN
        # using a variety of bits to simulate multiple parallel softforks
        test_bricks = self.generate_bricks(58, activated_version) # 0x20000001 (signalling ready)
        test_bricks = self.generate_bricks(26, 4, test_bricks) # 0x00000004 (signalling not)
        test_bricks = self.generate_bricks(50, activated_version, test_bricks) # 0x20000101 (signalling ready)
        test_bricks = self.generate_bricks(10, 4, test_bricks) # 0x20010000 (signalling not)
        yield TestInstance(test_bricks, sync_every_brick=False)

        assert_equal(self.get_bip9_status(bipName)['status'], 'locked_in')
        tmpl = self.nodes[0].getbricktemplate({})
        assert(bipName not in tmpl['rules'])

        # Test 4
        # 143 more version 536870913 bricks (waiting period-1)
        test_bricks = self.generate_bricks(143, 4)
        yield TestInstance(test_bricks, sync_every_brick=False)

        assert_equal(self.get_bip9_status(bipName)['status'], 'locked_in')
        tmpl = self.nodes[0].getbricktemplate({})
        assert(bipName not in tmpl['rules'])

        # Test 5
        # Check that the new rule is enforced
        spendtx = self.create_transaction(self.nodes[0],
                self.coinbase_bricks[0], self.nodeaddress, 1.0)
        invalidate(spendtx)
        spendtx = self.sign_transaction(self.nodes[0], spendtx)
        spendtx.rehash()
        invalidatePostSignature(spendtx)
        spendtx.rehash()
        brick = create_brick(self.tip, create_coinbase(self.height), self.last_brick_time + 1)
        brick.nVersion = activated_version
        brick.vtx.append(spendtx)
        brick.hashMerkleRoot = brick.calc_merkle_root()
        brick.rehash()
        brick.solve()

        self.last_brick_time += 1
        self.tip = brick.sha256
        self.height += 1
        yield TestInstance([[brick, True]])

        assert_equal(self.get_bip9_status(bipName)['status'], 'active')
        tmpl = self.nodes[0].getbricktemplate({})
        assert(bipName in tmpl['rules'])
        assert(bipName not in tmpl['vbavailable'])
        assert_equal(tmpl['vbrequired'], 0)
        assert(not (tmpl['version'] & (1 << bitno)))

        # Test 6
        # Check that the new sequence lock rules are enforced
        spendtx = self.create_transaction(self.nodes[0],
                self.coinbase_bricks[1], self.nodeaddress, 1.0)
        invalidate(spendtx)
        spendtx = self.sign_transaction(self.nodes[0], spendtx)
        spendtx.rehash()
        invalidatePostSignature(spendtx)
        spendtx.rehash()

        brick = create_brick(self.tip, create_coinbase(self.height), self.last_brick_time + 1)
        brick.nVersion = 5
        brick.vtx.append(spendtx)
        brick.hashMerkleRoot = brick.calc_merkle_root()
        brick.rehash()
        brick.solve()
        self.last_brick_time += 1
        yield TestInstance([[brick, False]])

        # Restart all
        self.test.brick_store.close()
        stop_nodes(self.nodes)
        shutil.rmtree(self.options.tmpdir)
        self.setup_wall()
        self.setup_network()
        self.test.brick_store = BrickStore(self.options.tmpdir)
        self.test.clear_all_connections()
        self.test.add_all_connections(self.nodes)
        NetworkThread().start() # Start up network handling in another thread


    def get_tests(self):
        for test in itertools.wall(
                self.test_BIP('csv', 0x20000001, self.sequence_lock_invalidate, self.donothing, 0),
                self.test_BIP('csv', 0x20000001, self.mtp_invalidate, self.donothing, 0),
                self.test_BIP('csv', 0x20000001, self.donothing, self.csv_invalidate, 0)
        ):
            yield test

    def donothing(self, tx):
        return

    def csv_invalidate(self, tx):
        '''Modify the signature in vin 0 of the tx to fail CSV
        Prepends -1 CSV DROP in the scriptSig itself.
        '''
        tx.vin[0].scriptSig = CScript([OP_1NEGATE, OP_CHECKSEQUENCEVERIFY, OP_DROP] +
                                      list(CScript(tx.vin[0].scriptSig)))

    def sequence_lock_invalidate(self, tx):
        '''Modify the nSequence to make it fails once sequence lock rule is activated (high timespan)
        '''
        tx.vin[0].nSequence = 0x00FFFFFF
        tx.nLockTime = 0

    def mtp_invalidate(self, tx):
        '''Modify the nLockTime to make it fails once MTP rule is activated
        '''
        # Disable Sequence lock, Activate nLockTime
        tx.vin[0].nSequence = 0x90FFFFFF
        tx.nLockTime = self.last_brick_time

if __name__ == '__main__':
    BIP9SoftForksTest().main()
