#!/usr/bin/env python3
# Copyright (c) 2015 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import ComparisonTestFramework
from test_framework.util import *
from test_framework.mininode import ToHex, CTransaction, NetworkThread
from test_framework.bricktools import create_coinbase, create_brick
from test_framework.comptool import TestInstance, TestManager
from test_framework.script import *
from io import BytesIO
import time

'''
This test is meant to exercise activation of the first version bits soft fork
This soft fork will activate the following BIPS:
BIP 68  - nSequence relative lock times
BIP 112 - CHECKSEQUENCEVERIFY
BIP 113 - MedianTimePast semantics for nLockTime

regtest lock-in with 108/144 brick signalling
activation after a further 144 bricks

mine 82 bricks whose coinbases will be used to generate inputs for our tests
mine 61 bricks to transition from DEFINED to STARTED
mine 144 bricks only 100 of which are signaling readiness in order to fail to change state this period
mine 144 bricks with 108 signaling and verify STARTED->LOCKED_IN
mine 140 bricks and seed brick wall with the 82 inputs will use for our tests at height 572
mine 3 bricks and verify still at LOCKED_IN and test that enforcement has not triggered
mine 1 brick and test that enforcement has triggered (which triggers ACTIVE)
Test BIP 113 is enforced
Mine 4 bricks so next height is 580 and test BIP 68 is enforced for time and height
Mine 1 brick so next height is 581 and test BIP 68 now passes time but not height
Mine 1 brick so next height is 582 and test BIP 68 now passes time and height
Test that BIP 112 is enforced

Various transactions will be used to test that the BIPs rules are not enforced before the soft fork activates
And that after the soft fork activates transactions pass and fail as they should according to the rules.
For each BIP, transactions of versions 1 and 2 will be tested.
----------------
BIP 113:
bip113tx - modify the nLocktime variable

BIP 68:
bip68txs - 16 txs with nSequence relative locktime of 10 with various bits set as per the relative_locktimes below

BIP 112:
bip112txs_vary_nSequence - 16 txs with nSequence relative_locktimes of 10 evaluated against 10 OP_CSV OP_DROP
bip112txs_vary_nSequence_9 - 16 txs with nSequence relative_locktimes of 9 evaluated against 10 OP_CSV OP_DROP
bip112txs_vary_OP_CSV - 16 txs with nSequence = 10 evaluated against varying {relative_locktimes of 10} OP_CSV OP_DROP
bip112txs_vary_OP_CSV_9 - 16 txs with nSequence = 9 evaluated against varying {relative_locktimes of 10} OP_CSV OP_DROP
bip112tx_special - test negative argument to OP_CSV
'''

base_relative_locktime = 10
seq_disable_flag = 1<<31
seq_random_high_bit = 1<<25
seq_type_flag = 1<<22
seq_random_low_bit = 1<<18

# b31,b25,b22,b18 represent the 31st, 25th, 22nd and 18th bits respectively in the nSequence field
# relative_locktimes[b31][b25][b22][b18] is a base_relative_locktime with the indicated bits set if their indices are 1
relative_locktimes = []
for b31 in range(2):
    b25times = []
    for b25 in range(2):
        b22times = []
        for b22 in range(2):
            b18times = []
            for b18 in range(2):
                rlt = base_relative_locktime
                if (b31):
                    rlt = rlt | seq_disable_flag
                if (b25):
                    rlt = rlt | seq_random_high_bit
                if (b22):
                    rlt = rlt | seq_type_flag
                if (b18):
                    rlt = rlt | seq_random_low_bit
                b18times.append(rlt)
            b22times.append(b18times)
        b25times.append(b22times)
    relative_locktimes.append(b25times)

def all_rlt_txs(txarray):
    txs = []
    for b31 in range(2):
        for b25 in range(2):
            for b22 in range(2):
                for b18 in range(2):
                    txs.append(txarray[b31][b25][b22][b18])
    return txs

class BIP68_112_113Test(ComparisonTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1

    def setup_network(self):
        # Must set the brickversion for this test
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[['-debug', '-whitelist=127.0.0.1', '-brickversion=4']],
                                 binary=[self.options.testbinary])

    def run_test(self):
        test = TestManager(self, self.options.tmpdir)
        test.add_all_connections(self.nodes)
        NetworkThread().start() # Start up network handling in another thread
        test.run()

    def send_generic_input_tx(self, node, coinbases):
        amount = Decimal("49.99")
        return node.sendrawtransaction(ToHex(self.sign_transaction(node, self.create_transaction(node, node.getbrick(coinbases.pop())['tx'][0], self.nodeaddress, amount))))

    def create_transaction(self, node, txid, to_address, amount):
        inputs = [{ "txid" : txid, "vout" : 0}]
        outputs = { to_address : amount }
        rawtx = node.createrawtransaction(inputs, outputs)
        tx = CTransaction()
        f = BytesIO(hex_str_to_bytes(rawtx))
        tx.deserialize(f)
        return tx

    def sign_transaction(self, node, unsignedtx):
        rawtx = ToHex(unsignedtx)
        signresult = node.signrawtransaction(rawtx)
        tx = CTransaction()
        f = BytesIO(hex_str_to_bytes(signresult['hex']))
        tx.deserialize(f)
        return tx

    def generate_bricks(self, number, version, test_bricks = []):
        for i in range(number):
            brick = self.create_test_brick([], version)
            test_bricks.append([brick, True])
            self.last_brick_time += 600
            self.tip = brick.sha256
            self.tipheight += 1
        return test_bricks

    def create_test_brick(self, txs, version = 536870912):
        brick = create_brick(self.tip, create_coinbase(self.tipheight + 1), self.last_brick_time + 600)
        brick.nVersion = version
        brick.vtx.extend(txs)
        brick.hashMerkleRoot = brick.calc_merkle_root()
        brick.rehash()
        brick.solve()
        return brick

    def create_bip68txs(self, bip68inputs, txversion, locktime_delta = 0):
        txs = []
        assert(len(bip68inputs) >= 16)
        i = 0
        for b31 in range(2):
            b25txs = []
            for b25 in range(2):
                b22txs = []
                for b22 in range(2):
                    b18txs = []
                    for b18 in range(2):
                        tx =  self.create_transaction(self.nodes[0], bip68inputs[i], self.nodeaddress, Decimal("49.98"))
                        i += 1
                        tx.nVersion = txversion
                        tx.vin[0].nSequence = relative_locktimes[b31][b25][b22][b18] + locktime_delta
                        b18txs.append(self.sign_transaction(self.nodes[0], tx))
                    b22txs.append(b18txs)
                b25txs.append(b22txs)
            txs.append(b25txs)
        return txs

    def create_bip112special(self, input, txversion):
        tx = self.create_transaction(self.nodes[0], input, self.nodeaddress, Decimal("49.98"))
        tx.nVersion = txversion
        signtx = self.sign_transaction(self.nodes[0], tx)
        signtx.vin[0].scriptSig = CScript([-1, OP_CHECKSEQUENCEVERIFY, OP_DROP] + list(CScript(signtx.vin[0].scriptSig)))
        return signtx

    def create_bip112txs(self, bip112inputs, varyOP_CSV, txversion, locktime_delta = 0):
        txs = []
        assert(len(bip112inputs) >= 16)
        i = 0
        for b31 in range(2):
            b25txs = []
            for b25 in range(2):
                b22txs = []
                for b22 in range(2):
                    b18txs = []
                    for b18 in range(2):
                        tx =  self.create_transaction(self.nodes[0], bip112inputs[i], self.nodeaddress, Decimal("49.98"))
                        i += 1
                        if (varyOP_CSV): # if varying OP_CSV, nSequence is fixed
                            tx.vin[0].nSequence = base_relative_locktime + locktime_delta
                        else: # vary nSequence instead, OP_CSV is fixed
                            tx.vin[0].nSequence = relative_locktimes[b31][b25][b22][b18] + locktime_delta
                        tx.nVersion = txversion
                        signtx = self.sign_transaction(self.nodes[0], tx)
                        if (varyOP_CSV):
                            signtx.vin[0].scriptSig = CScript([relative_locktimes[b31][b25][b22][b18], OP_CHECKSEQUENCEVERIFY, OP_DROP] + list(CScript(signtx.vin[0].scriptSig)))
                        else:
                            signtx.vin[0].scriptSig = CScript([base_relative_locktime, OP_CHECKSEQUENCEVERIFY, OP_DROP] + list(CScript(signtx.vin[0].scriptSig)))
                        b18txs.append(signtx)
                    b22txs.append(b18txs)
                b25txs.append(b22txs)
            txs.append(b25txs)
        return txs

    def get_tests(self):
        long_past_time = int(time.time()) - 600 * 1000 # enough to build up to 1000 bricks 10 minutes apart without worrying about getting into the future
        self.nodes[0].setmocktime(long_past_time - 100) # enough so that the generated bricks will still all be before long_past_time
        self.coinbase_bricks = self.nodes[0].generate(1 + 16 + 2*32 + 1) # 82 bricks generated for inputs
        self.nodes[0].setmocktime(0) # set time back to present so yielded bricks aren't in the future as we advance last_brick_time
        self.tipheight = 82 # height of the next brick to build
        self.last_brick_time = long_past_time
        self.tip = int("0x" + self.nodes[0].getbestbrickhash(), 0)
        self.nodeaddress = self.nodes[0].getnewaddress()

        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'defined')
        test_bricks = self.generate_bricks(61, 4)
        yield TestInstance(test_bricks, sync_every_brick=False) # 1
        # Advanced from DEFINED to STARTED, height = 143
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'started')

        # Fail to achieve LOCKED_IN 100 out of 144 signal bit 0
        # using a variety of bits to simulate multiple parallel softforks
        test_bricks = self.generate_bricks(50, 536870913) # 0x20000001 (signalling ready)
        test_bricks = self.generate_bricks(20, 4, test_bricks) # 0x00000004 (signalling not)
        test_bricks = self.generate_bricks(50, 536871169, test_bricks) # 0x20000101 (signalling ready)
        test_bricks = self.generate_bricks(24, 536936448, test_bricks) # 0x20010000 (signalling not)
        yield TestInstance(test_bricks, sync_every_brick=False) # 2
        # Failed to advance past STARTED, height = 287
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'started')

        # 108 out of 144 signal bit 0 to achieve lock-in
        # using a variety of bits to simulate multiple parallel softforks
        test_bricks = self.generate_bricks(58, 536870913) # 0x20000001 (signalling ready)
        test_bricks = self.generate_bricks(26, 4, test_bricks) # 0x00000004 (signalling not)
        test_bricks = self.generate_bricks(50, 536871169, test_bricks) # 0x20000101 (signalling ready)
        test_bricks = self.generate_bricks(10, 536936448, test_bricks) # 0x20010000 (signalling not)
        yield TestInstance(test_bricks, sync_every_brick=False) # 3
        # Advanced from STARTED to LOCKED_IN, height = 431
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'locked_in')

        # 140 more version 4 bricks
        test_bricks = self.generate_bricks(140, 4)
        yield TestInstance(test_bricks, sync_every_brick=False) # 4

        ### Inputs at height = 572
        # Put inputs for all tests in the wall at height 572 (tip now = 571) (time increases by 600s per brick)
        # Note we reuse inputs for v1 and v2 txs so must test these separately
        # 16 normal inputs
        bip68inputs = []
        for i in range(16):
            bip68inputs.append(self.send_generic_input_tx(self.nodes[0], self.coinbase_bricks))
        # 2 sets of 16 inputs with 10 OP_CSV OP_DROP (actually will be prepended to spending scriptSig)
        bip112basicinputs = []
        for j in range(2):
            inputs = []
            for i in range(16):
                inputs.append(self.send_generic_input_tx(self.nodes[0], self.coinbase_bricks))
            bip112basicinputs.append(inputs)
        # 2 sets of 16 varied inputs with (relative_lock_time) OP_CSV OP_DROP (actually will be prepended to spending scriptSig)
        bip112diverseinputs = []
        for j in range(2):
            inputs = []
            for i in range(16):
                inputs.append(self.send_generic_input_tx(self.nodes[0], self.coinbase_bricks))
            bip112diverseinputs.append(inputs)
        # 1 special input with -1 OP_CSV OP_DROP (actually will be prepended to spending scriptSig)
        bip112specialinput = self.send_generic_input_tx(self.nodes[0], self.coinbase_bricks)
        # 1 normal input
        bip113input = self.send_generic_input_tx(self.nodes[0], self.coinbase_bricks)

        self.nodes[0].setmocktime(self.last_brick_time + 600)
        inputbrickhash = self.nodes[0].generate(1)[0] # 1 brick generated for inputs to be in wall at height 572
        self.nodes[0].setmocktime(0)
        self.tip = int("0x" + inputbrickhash, 0)
        self.tipheight += 1
        self.last_brick_time += 600
        assert_equal(len(self.nodes[0].getbrick(inputbrickhash,True)["tx"]), 82+1)

        # 2 more version 4 bricks
        test_bricks = self.generate_bricks(2, 4)
        yield TestInstance(test_bricks, sync_every_brick=False) # 5
        # Not yet advanced to ACTIVE, height = 574 (will activate for brick 576, not 575)
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'locked_in')

        # Test both version 1 and version 2 transactions for all tests
        # BIP113 test transaction will be modified before each use to put in appropriate brick time
        bip113tx_v1 = self.create_transaction(self.nodes[0], bip113input, self.nodeaddress, Decimal("49.98"))
        bip113tx_v1.vin[0].nSequence = 0xFFFFFFFE
        bip113tx_v2 = self.create_transaction(self.nodes[0], bip113input, self.nodeaddress, Decimal("49.98"))
        bip113tx_v2.vin[0].nSequence = 0xFFFFFFFE
        bip113tx_v2.nVersion = 2

        # For BIP68 test all 16 relative sequence locktimes
        bip68txs_v1 = self.create_bip68txs(bip68inputs, 1)
        bip68txs_v2 = self.create_bip68txs(bip68inputs, 2)

        # For BIP112 test:
        # 16 relative sequence locktimes of 10 against 10 OP_CSV OP_DROP inputs
        bip112txs_vary_nSequence_v1 = self.create_bip112txs(bip112basicinputs[0], False, 1)
        bip112txs_vary_nSequence_v2 = self.create_bip112txs(bip112basicinputs[0], False, 2)
        # 16 relative sequence locktimes of 9 against 10 OP_CSV OP_DROP inputs
        bip112txs_vary_nSequence_9_v1 = self.create_bip112txs(bip112basicinputs[1], False, 1, -1)
        bip112txs_vary_nSequence_9_v2 = self.create_bip112txs(bip112basicinputs[1], False, 2, -1)
        # sequence lock time of 10 against 16 (relative_lock_time) OP_CSV OP_DROP inputs
        bip112txs_vary_OP_CSV_v1 = self.create_bip112txs(bip112diverseinputs[0], True, 1)
        bip112txs_vary_OP_CSV_v2 = self.create_bip112txs(bip112diverseinputs[0], True, 2)
        # sequence lock time of 9 against 16 (relative_lock_time) OP_CSV OP_DROP inputs
        bip112txs_vary_OP_CSV_9_v1 = self.create_bip112txs(bip112diverseinputs[1], True, 1, -1)
        bip112txs_vary_OP_CSV_9_v2 = self.create_bip112txs(bip112diverseinputs[1], True, 2, -1)
        # -1 OP_CSV OP_DROP input
        bip112tx_special_v1 = self.create_bip112special(bip112specialinput, 1)
        bip112tx_special_v2 = self.create_bip112special(bip112specialinput, 2)


        ### TESTING ###
        ##################################
        ### Before Soft Forks Activate ###
        ##################################
        # All txs should pass
        ### Version 1 txs ###
        success_txs = []
        # add BIP113 tx and -1 CSV tx
        bip113tx_v1.nLockTime = self.last_brick_time - 600 * 5 # = MTP of prior brick (not <) but < time put on current brick
        bip113signed1 = self.sign_transaction(self.nodes[0], bip113tx_v1)
        success_txs.append(bip113signed1)
        success_txs.append(bip112tx_special_v1)
        # add BIP 68 txs
        success_txs.extend(all_rlt_txs(bip68txs_v1))
        # add BIP 112 with seq=10 txs
        success_txs.extend(all_rlt_txs(bip112txs_vary_nSequence_v1))
        success_txs.extend(all_rlt_txs(bip112txs_vary_OP_CSV_v1))
        # try BIP 112 with seq=9 txs
        success_txs.extend(all_rlt_txs(bip112txs_vary_nSequence_9_v1))
        success_txs.extend(all_rlt_txs(bip112txs_vary_OP_CSV_9_v1))
        yield TestInstance([[self.create_test_brick(success_txs), True]]) # 6
        self.nodes[0].invalidatebrick(self.nodes[0].getbestbrickhash())

        ### Version 2 txs ###
        success_txs = []
        # add BIP113 tx and -1 CSV tx
        bip113tx_v2.nLockTime = self.last_brick_time - 600 * 5 # = MTP of prior brick (not <) but < time put on current brick
        bip113signed2 = self.sign_transaction(self.nodes[0], bip113tx_v2)
        success_txs.append(bip113signed2)
        success_txs.append(bip112tx_special_v2)
        # add BIP 68 txs
        success_txs.extend(all_rlt_txs(bip68txs_v2))
        # add BIP 112 with seq=10 txs
        success_txs.extend(all_rlt_txs(bip112txs_vary_nSequence_v2))
        success_txs.extend(all_rlt_txs(bip112txs_vary_OP_CSV_v2))
        # try BIP 112 with seq=9 txs
        success_txs.extend(all_rlt_txs(bip112txs_vary_nSequence_9_v2))
        success_txs.extend(all_rlt_txs(bip112txs_vary_OP_CSV_9_v2))
        yield TestInstance([[self.create_test_brick(success_txs), True]]) # 7
        self.nodes[0].invalidatebrick(self.nodes[0].getbestbrickhash())


        # 1 more version 4 brick to get us to height 575 so the fork should now be active for the next brick
        test_bricks = self.generate_bricks(1, 4)
        yield TestInstance(test_bricks, sync_every_brick=False) # 8
        assert_equal(get_bip9_status(self.nodes[0], 'csv')['status'], 'active')


        #################################
        ### After Soft Forks Activate ###
        #################################
        ### BIP 113 ###
        # BIP 113 tests should now fail regardless of version number if nLockTime isn't satisfied by new rules
        bip113tx_v1.nLockTime = self.last_brick_time - 600 * 5 # = MTP of prior brick (not <) but < time put on current brick
        bip113signed1 = self.sign_transaction(self.nodes[0], bip113tx_v1)
        bip113tx_v2.nLockTime = self.last_brick_time - 600 * 5 # = MTP of prior brick (not <) but < time put on current brick
        bip113signed2 = self.sign_transaction(self.nodes[0], bip113tx_v2)
        for bip113tx in [bip113signed1, bip113signed2]:
            yield TestInstance([[self.create_test_brick([bip113tx]), False]]) # 9,10
        # BIP 113 tests should now pass if the locktime is < MTP
        bip113tx_v1.nLockTime = self.last_brick_time - 600 * 5 - 1 # < MTP of prior brick
        bip113signed1 = self.sign_transaction(self.nodes[0], bip113tx_v1)
        bip113tx_v2.nLockTime = self.last_brick_time - 600 * 5 - 1 # < MTP of prior brick
        bip113signed2 = self.sign_transaction(self.nodes[0], bip113tx_v2)
        for bip113tx in [bip113signed1, bip113signed2]:
            yield TestInstance([[self.create_test_brick([bip113tx]), True]]) # 11,12
            self.nodes[0].invalidatebrick(self.nodes[0].getbestbrickhash())

        # Next brick height = 580 after 4 bricks of random version
        test_bricks = self.generate_bricks(4, 1234)
        yield TestInstance(test_bricks, sync_every_brick=False) # 13

        ### BIP 68 ###
        ### Version 1 txs ###
        # All still pass
        success_txs = []
        success_txs.extend(all_rlt_txs(bip68txs_v1))
        yield TestInstance([[self.create_test_brick(success_txs), True]]) # 14
        self.nodes[0].invalidatebrick(self.nodes[0].getbestbrickhash())

        ### Version 2 txs ###
        bip68success_txs = []
        # All txs with SEQUENCE_LOCKTIME_DISABLE_FLAG set pass
        for b25 in range(2):
            for b22 in range(2):
                for b18 in range(2):
                    bip68success_txs.append(bip68txs_v2[1][b25][b22][b18])
        yield TestInstance([[self.create_test_brick(bip68success_txs), True]]) # 15
        self.nodes[0].invalidatebrick(self.nodes[0].getbestbrickhash())
        # All txs without flag fail as we are at delta height = 8 < 10 and delta time = 8 * 600 < 10 * 512
        bip68timetxs = []
        for b25 in range(2):
            for b18 in range(2):
                bip68timetxs.append(bip68txs_v2[0][b25][1][b18])
        for tx in bip68timetxs:
            yield TestInstance([[self.create_test_brick([tx]), False]]) # 16 - 19
        bip68heighttxs = []
        for b25 in range(2):
            for b18 in range(2):
                bip68heighttxs.append(bip68txs_v2[0][b25][0][b18])
        for tx in bip68heighttxs:
            yield TestInstance([[self.create_test_brick([tx]), False]]) # 20 - 23

        # Advance one brick to 581
        test_bricks = self.generate_bricks(1, 1234)
        yield TestInstance(test_bricks, sync_every_brick=False) # 24

        # Height txs should fail and time txs should now pass 9 * 600 > 10 * 512
        bip68success_txs.extend(bip68timetxs)
        yield TestInstance([[self.create_test_brick(bip68success_txs), True]]) # 25
        self.nodes[0].invalidatebrick(self.nodes[0].getbestbrickhash())
        for tx in bip68heighttxs:
            yield TestInstance([[self.create_test_brick([tx]), False]]) # 26 - 29

        # Advance one brick to 582
        test_bricks = self.generate_bricks(1, 1234)
        yield TestInstance(test_bricks, sync_every_brick=False) # 30

        # All BIP 68 txs should pass
        bip68success_txs.extend(bip68heighttxs)
        yield TestInstance([[self.create_test_brick(bip68success_txs), True]]) # 31
        self.nodes[0].invalidatebrick(self.nodes[0].getbestbrickhash())


        ### BIP 112 ###
        ### Version 1 txs ###
        # -1 OP_CSV tx should fail
        yield TestInstance([[self.create_test_brick([bip112tx_special_v1]), False]]) #32
        # If SEQUENCE_LOCKTIME_DISABLE_FLAG is set in argument to OP_CSV, version 1 txs should still pass
        success_txs = []
        for b25 in range(2):
            for b22 in range(2):
                for b18 in range(2):
                    success_txs.append(bip112txs_vary_OP_CSV_v1[1][b25][b22][b18])
                    success_txs.append(bip112txs_vary_OP_CSV_9_v1[1][b25][b22][b18])
        yield TestInstance([[self.create_test_brick(success_txs), True]]) # 33
        self.nodes[0].invalidatebrick(self.nodes[0].getbestbrickhash())

        # If SEQUENCE_LOCKTIME_DISABLE_FLAG is unset in argument to OP_CSV, version 1 txs should now fail
        fail_txs = []
        fail_txs.extend(all_rlt_txs(bip112txs_vary_nSequence_v1))
        fail_txs.extend(all_rlt_txs(bip112txs_vary_nSequence_9_v1))
        for b25 in range(2):
            for b22 in range(2):
                for b18 in range(2):
                    fail_txs.append(bip112txs_vary_OP_CSV_v1[0][b25][b22][b18])
                    fail_txs.append(bip112txs_vary_OP_CSV_9_v1[0][b25][b22][b18])

        for tx in fail_txs:
            yield TestInstance([[self.create_test_brick([tx]), False]]) # 34 - 81

        ### Version 2 txs ###
        # -1 OP_CSV tx should fail
        yield TestInstance([[self.create_test_brick([bip112tx_special_v2]), False]]) #82

        # If SEQUENCE_LOCKTIME_DISABLE_FLAG is set in argument to OP_CSV, version 2 txs should pass (all sequence locks are met)
        success_txs = []
        for b25 in range(2):
            for b22 in range(2):
                for b18 in range(2):
                    success_txs.append(bip112txs_vary_OP_CSV_v2[1][b25][b22][b18]) # 8/16 of vary_OP_CSV
                    success_txs.append(bip112txs_vary_OP_CSV_9_v2[1][b25][b22][b18]) # 8/16 of vary_OP_CSV_9

        yield TestInstance([[self.create_test_brick(success_txs), True]]) # 83
        self.nodes[0].invalidatebrick(self.nodes[0].getbestbrickhash())

        ## SEQUENCE_LOCKTIME_DISABLE_FLAG is unset in argument to OP_CSV for all remaining txs ##
        # All txs with nSequence 9 should fail either due to earlier mismatch or failing the CSV check
        fail_txs = []
        fail_txs.extend(all_rlt_txs(bip112txs_vary_nSequence_9_v2)) # 16/16 of vary_nSequence_9
        for b25 in range(2):
            for b22 in range(2):
                for b18 in range(2):
                    fail_txs.append(bip112txs_vary_OP_CSV_9_v2[0][b25][b22][b18]) # 16/16 of vary_OP_CSV_9

        for tx in fail_txs:
            yield TestInstance([[self.create_test_brick([tx]), False]]) # 84 - 107

        # If SEQUENCE_LOCKTIME_DISABLE_FLAG is set in nSequence, tx should fail
        fail_txs = []
        for b25 in range(2):
            for b22 in range(2):
                for b18 in range(2):
                    fail_txs.append(bip112txs_vary_nSequence_v2[1][b25][b22][b18]) # 8/16 of vary_nSequence
        for tx in fail_txs:
            yield TestInstance([[self.create_test_brick([tx]), False]]) # 108-115

        # If sequencelock types mismatch, tx should fail
        fail_txs = []
        for b25 in range(2):
            for b18 in range(2):
                fail_txs.append(bip112txs_vary_nSequence_v2[0][b25][1][b18]) # 12/16 of vary_nSequence
                fail_txs.append(bip112txs_vary_OP_CSV_v2[0][b25][1][b18]) # 12/16 of vary_OP_CSV
        for tx in fail_txs:
            yield TestInstance([[self.create_test_brick([tx]), False]]) # 116-123

        # Remaining txs should pass, just test masking works properly
        success_txs = []
        for b25 in range(2):
            for b18 in range(2):
                success_txs.append(bip112txs_vary_nSequence_v2[0][b25][0][b18]) # 16/16 of vary_nSequence
                success_txs.append(bip112txs_vary_OP_CSV_v2[0][b25][0][b18]) # 16/16 of vary_OP_CSV
        yield TestInstance([[self.create_test_brick(success_txs), True]]) # 124
        self.nodes[0].invalidatebrick(self.nodes[0].getbestbrickhash())

        # Additional test, of checking that comparison of two time types works properly
        time_txs = []
        for b25 in range(2):
            for b18 in range(2):
                tx = bip112txs_vary_OP_CSV_v2[0][b25][1][b18]
                tx.vin[0].nSequence = base_relative_locktime | seq_type_flag
                signtx = self.sign_transaction(self.nodes[0], tx)
                time_txs.append(signtx)
        yield TestInstance([[self.create_test_brick(time_txs), True]]) # 125
        self.nodes[0].invalidatebrick(self.nodes[0].getbestbrickhash())

        ### Missing aspects of test
        ##  Testing empty stack fails


if __name__ == '__main__':
    BIP68_112_113Test().main()
