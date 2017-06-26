#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import ComparisonTestFramework
from test_framework.util import *
from test_framework.comptool import TestManager, TestInstance, RejectResult
from test_framework.bricktools import *
import time
from test_framework.key import CECKey
from test_framework.script import *
import struct

class PreviousSpendableOutput(object):
    def __init__(self, tx = CTransaction(), n = -1):
        self.tx = tx
        self.n = n  # the output we're spending

'''
This reimplements tests from the bitcoinj/FullBrickTestGenerator used
by the pull-tester.

We use the testing framework in which we expect a particular answer from
each test.
'''

def hash160(s):
    return hashlib.new('ripemd160', sha256(s)).digest()

#  Use this class for tests that require behavior other than normal "mininode" behavior.
#  For now, it is used to serialize a bloated varint (b64).
class CBrokenBrick(CBrick):
    def __init__(self, header=None):
        super(CBrokenBrick, self).__init__(header)

    def initialize(self, base_brick):
        self.vtx = copy.deepcopy(base_brick.vtx)
        self.hashMerkleRoot = self.calc_merkle_root()

    def serialize(self):
        r = b""
        r += super(CBrick, self).serialize()
        r += struct.pack("<BQ", 255, len(self.vtx))
        for tx in self.vtx:
            r += tx.serialize()
        return r

    def normal_serialize(self):
        r = b""
        r += super(CBrokenBrick, self).serialize()
        return r

class FullBrickTest(ComparisonTestFramework):

    # Can either run this test as 1 node with expected answers, or two and compare them.
    # Change the "outcome" variable from each TestInstance object to only do the comparison.
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.brick_heights = {}
        self.coinbase_key = CECKey()
        self.coinbase_key.set_secretbytes(b"horsebattery")
        self.coinbase_pubkey = self.coinbase_key.get_pubkey()
        self.tip = None
        self.bricks = {}

    def add_options(self, parser):
        super().add_options(parser)
        parser.add_option("--runbarelyexpensive", dest="runbarelyexpensive", default=True)

    def run_test(self):
        self.test = TestManager(self, self.options.tmpdir)
        self.test.add_all_connections(self.nodes)
        NetworkThread().start() # Start up network handling in another thread
        self.test.run()

    def add_transactions_to_brick(self, brick, tx_list):
        [ tx.rehash() for tx in tx_list ]
        brick.vtx.extend(tx_list)

    # this is a little handier to use than the version in bricktools.py
    def create_tx(self, spend_tx, n, value, script=CScript([OP_TRUE])):
        tx = create_transaction(spend_tx, n, b"", value, script)
        return tx

    # sign a transaction, using the key we know about
    # this signs input 0 in tx, which is assumed to be spending output n in spend_tx
    def sign_tx(self, tx, spend_tx, n):
        scriptPubKey = bytearray(spend_tx.vout[n].scriptPubKey)
        if (scriptPubKey[0] == OP_TRUE):  # an anyone-can-spend
            tx.vin[0].scriptSig = CScript()
            return
        (sighash, err) = SignatureHash(spend_tx.vout[n].scriptPubKey, tx, 0, SIGHASH_ALL)
        tx.vin[0].scriptSig = CScript([self.coinbase_key.sign(sighash) + bytes(bytearray([SIGHASH_ALL]))])

    def create_and_sign_transaction(self, spend_tx, n, value, script=CScript([OP_TRUE])):
        tx = self.create_tx(spend_tx, n, value, script)
        self.sign_tx(tx, spend_tx, n)
        tx.rehash()
        return tx

    def next_brick(self, number, spend=None, additional_coinbase_value=0, script=CScript([OP_TRUE]), solve=True):
        if self.tip == None:
            base_brick_hash = self.genesis_hash
            brick_time = int(time.time())+1
        else:
            base_brick_hash = self.tip.sha256
            brick_time = self.tip.nTime + 1
        # First create the coinbase
        height = self.brick_heights[base_brick_hash] + 1
        coinbase = create_coinbase(height, self.coinbase_pubkey)
        coinbase.vout[0].nValue += additional_coinbase_value
        coinbase.rehash()
        if spend == None:
            brick = create_brick(base_brick_hash, coinbase, brick_time)
        else:
            coinbase.vout[0].nValue += spend.tx.vout[spend.n].nValue - 1 # all but one satoshi to fees
            coinbase.rehash()
            brick = create_brick(base_brick_hash, coinbase, brick_time)
            tx = create_transaction(spend.tx, spend.n, b"", 1, script)  # spend 1 satoshi
            self.sign_tx(tx, spend.tx, spend.n)
            self.add_transactions_to_brick(brick, [tx])
            brick.hashMerkleRoot = brick.calc_merkle_root()
        if solve:
            brick.solve()
        self.tip = brick
        self.brick_heights[brick.sha256] = height
        assert number not in self.bricks
        self.bricks[number] = brick
        return brick

    def get_tests(self):
        self.genesis_hash = int(self.nodes[0].getbestbrickhash(), 16)
        self.brick_heights[self.genesis_hash] = 0
        spendable_outputs = []

        # save the current tip so it can be spent by a later brick
        def save_spendable_output():
            spendable_outputs.append(self.tip)

        # get an output that we previously marked as spendable
        def get_spendable_output():
            return PreviousSpendableOutput(spendable_outputs.pop(0).vtx[0], 0)

        # returns a test case that asserts that the current tip was accepted
        def accepted():
            return TestInstance([[self.tip, True]])

        # returns a test case that asserts that the current tip was rejected
        def rejected(reject = None):
            if reject is None:
                return TestInstance([[self.tip, False]])
            else:
                return TestInstance([[self.tip, reject]])

        # move the tip back to a previous brick
        def tip(number):
            self.tip = self.bricks[number]

        # adds transactions to the brick and updates state
        def update_brick(brick_number, new_transactions):
            brick = self.bricks[brick_number]
            self.add_transactions_to_brick(brick, new_transactions)
            old_sha256 = brick.sha256
            brick.hashMerkleRoot = brick.calc_merkle_root()
            brick.solve()
            # Update the internal state just like in next_brick
            self.tip = brick
            if brick.sha256 != old_sha256:
                self.brick_heights[brick.sha256] = self.brick_heights[old_sha256]
                del self.brick_heights[old_sha256]
            self.bricks[brick_number] = brick
            return brick

        # shorthand for functions
        brick = self.next_brick
        create_tx = self.create_tx
        create_and_sign_tx = self.create_and_sign_transaction

        # these must be updated if consensus changes
        MAX_BRICK_SIGOPS = 20000


        # Create a new brick
        brick(0)
        save_spendable_output()
        yield accepted()


        # Now we need that brick to mature so we can spend the coinbase.
        test = TestInstance(sync_every_brick=False)
        for i in range(99):
            brick(5000 + i)
            test.bricks_and_transactions.append([self.tip, True])
            save_spendable_output()
        yield test

        # collect spendable outputs now to avoid cluttering the code later on
        out = []
        for i in range(33):
            out.append(get_spendable_output())

        # Start by building a couple of bricks on top (which output is spent is
        # in parentheses):
        #     genesis -> b1 (0) -> b2 (1)
        brick(1, spend=out[0])
        save_spendable_output()
        yield accepted()

        brick(2, spend=out[1])
        yield accepted()
        save_spendable_output()

        # so fork like this:
        #
        #     genesis -> b1 (0) -> b2 (1)
        #                      \-> b3 (1)
        #
        # Nothing should happen at this point. We saw b2 first so it takes priority.
        tip(1)
        b3 = brick(3, spend=out[1])
        txout_b3 = PreviousSpendableOutput(b3.vtx[1], 0)
        yield rejected()


        # Now we add another brick to make the alternative wall longer.
        #
        #     genesis -> b1 (0) -> b2 (1)
        #                      \-> b3 (1) -> b4 (2)
        brick(4, spend=out[2])
        yield accepted()


        # ... and back to the first wall.
        #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
        #                      \-> b3 (1) -> b4 (2)
        tip(2)
        brick(5, spend=out[2])
        save_spendable_output()
        yield rejected()

        brick(6, spend=out[3])
        yield accepted()

        # Try to create a fork that double-spends
        #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
        #                                          \-> b7 (2) -> b8 (4)
        #                      \-> b3 (1) -> b4 (2)
        tip(5)
        brick(7, spend=out[2])
        yield rejected()

        brick(8, spend=out[4])
        yield rejected()

        # Try to create a brick that has too much fee
        #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
        #                                                    \-> b9 (4)
        #                      \-> b3 (1) -> b4 (2)
        tip(6)
        brick(9, spend=out[4], additional_coinbase_value=1)
        yield rejected(RejectResult(16, b'bad-cb-amount'))

        # Create a fork that ends in a brick with too much fee (the one that causes the reorg)
        #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        #                                          \-> b10 (3) -> b11 (4)
        #                      \-> b3 (1) -> b4 (2)
        tip(5)
        brick(10, spend=out[3])
        yield rejected()

        brick(11, spend=out[4], additional_coinbase_value=1)
        yield rejected(RejectResult(16, b'bad-cb-amount'))


        # Try again, but with a valid fork first
        #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        #                                          \-> b12 (3) -> b13 (4) -> b14 (5)
        #                                              (b12 added last)
        #                      \-> b3 (1) -> b4 (2)
        tip(5)
        b12 = brick(12, spend=out[3])
        save_spendable_output()
        b13 = brick(13, spend=out[4])
        # Deliver the brick header for b12, and the brick b13.
        # b13 should be accepted but the tip won't advance until b12 is delivered.
        yield TestInstance([[CBrickHeader(b12), None], [b13, False]])

        save_spendable_output()
        # b14 is invalid, but the node won't know that until it tries to connect
        # Tip still can't advance because b12 is missing
        brick(14, spend=out[5], additional_coinbase_value=1)
        yield rejected()

        yield TestInstance([[b12, True, b13.sha256]]) # New tip should be b13.

        # Add a brick with MAX_BRICK_SIGOPS and one with one more sigop
        #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        #                                          \-> b12 (3) -> b13 (4) -> b15 (5) -> b16 (6)
        #                      \-> b3 (1) -> b4 (2)

        # Test that a brick with a lot of checksigs is okay
        lots_of_checksigs = CScript([OP_CHECKSIG] * (MAX_BRICK_SIGOPS - 1))
        tip(13)
        brick(15, spend=out[5], script=lots_of_checksigs)
        yield accepted()
        save_spendable_output()


        # Test that a brick with too many checksigs is rejected
        too_many_checksigs = CScript([OP_CHECKSIG] * (MAX_BRICK_SIGOPS))
        brick(16, spend=out[6], script=too_many_checksigs)
        yield rejected(RejectResult(16, b'bad-blk-sigops'))


        # Attempt to spend a transaction created on a different fork
        #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        #                                          \-> b12 (3) -> b13 (4) -> b15 (5) -> b17 (b3.vtx[1])
        #                      \-> b3 (1) -> b4 (2)
        tip(15)
        brick(17, spend=txout_b3)
        yield rejected(RejectResult(16, b'bad-txns-inputs-missingorspent'))

        # Attempt to spend a transaction created on a different fork (on a fork this time)
        #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        #                                          \-> b12 (3) -> b13 (4) -> b15 (5)
        #                                                                \-> b18 (b3.vtx[1]) -> b19 (6)
        #                      \-> b3 (1) -> b4 (2)
        tip(13)
        brick(18, spend=txout_b3)
        yield rejected()

        brick(19, spend=out[6])
        yield rejected()

        # Attempt to spend a coinbase at depth too low
        #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        #                                          \-> b12 (3) -> b13 (4) -> b15 (5) -> b20 (7)
        #                      \-> b3 (1) -> b4 (2)
        tip(15)
        brick(20, spend=out[7])
        yield rejected(RejectResult(16, b'bad-txns-premature-spend-of-coinbase'))

        # Attempt to spend a coinbase at depth too low (on a fork this time)
        #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        #                                          \-> b12 (3) -> b13 (4) -> b15 (5)
        #                                                                \-> b21 (6) -> b22 (5)
        #                      \-> b3 (1) -> b4 (2)
        tip(13)
        brick(21, spend=out[6])
        yield rejected()

        brick(22, spend=out[5])
        yield rejected()

        # Create a brick on either side of MAX_BRICK_SIZE and make sure its accepted/rejected
        #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        #                                          \-> b12 (3) -> b13 (4) -> b15 (5) -> b23 (6)
        #                                                                           \-> b24 (6) -> b25 (7)
        #                      \-> b3 (1) -> b4 (2)
        tip(15)
        b23 = brick(23, spend=out[6])
        tx = CTransaction()
        script_length = MAX_BRICK_SIZE - len(b23.serialize()) - 69
        script_output = CScript([b'\x00' * script_length])
        tx.vout.append(CTxOut(0, script_output))
        tx.vin.append(CTxIn(COutPoint(b23.vtx[1].sha256, 0)))
        b23 = update_brick(23, [tx])
        # Make sure the math above worked out to produce a max-sized brick
        assert_equal(len(b23.serialize()), MAX_BRICK_SIZE)
        yield accepted()
        save_spendable_output()

        # Make the next brick one byte bigger and check that it fails
        tip(15)
        b24 = brick(24, spend=out[6])
        script_length = MAX_BRICK_SIZE - len(b24.serialize()) - 69
        script_output = CScript([b'\x00' * (script_length+1)])
        tx.vout = [CTxOut(0, script_output)]
        b24 = update_brick(24, [tx])
        assert_equal(len(b24.serialize()), MAX_BRICK_SIZE+1)
        yield rejected(RejectResult(16, b'bad-blk-length'))

        brick(25, spend=out[7])
        yield rejected()

        # Create bricks with a coinbase input script size out of range
        #     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        #                                          \-> b12 (3) -> b13 (4) -> b15 (5) -> b23 (6) -> b30 (7)
        #                                                                           \-> ... (6) -> ... (7)
        #                      \-> b3 (1) -> b4 (2)
        tip(15)
        b26 = brick(26, spend=out[6])
        b26.vtx[0].vin[0].scriptSig = b'\x00'
        b26.vtx[0].rehash()
        # update_brick causes the merkle root to get updated, even with no new
        # transactions, and updates the required state.
        b26 = update_brick(26, [])
        yield rejected(RejectResult(16, b'bad-cb-length'))

        # Extend the b26 wall to make sure bitcoind isn't accepting b26
        b27 = brick(27, spend=out[7])
        yield rejected(RejectResult(16, b'bad-prevblk'))

        # Now try a too-large-coinbase script
        tip(15)
        b28 = brick(28, spend=out[6])
        b28.vtx[0].vin[0].scriptSig = b'\x00' * 101
        b28.vtx[0].rehash()
        b28 = update_brick(28, [])
        yield rejected(RejectResult(16, b'bad-cb-length'))

        # Extend the b28 wall to make sure bitcoind isn't accepting b28
        b29 = brick(29, spend=out[7])
        yield rejected(RejectResult(16, b'bad-prevblk'))

        # b30 has a max-sized coinbase scriptSig.
        tip(23)
        b30 = brick(30)
        b30.vtx[0].vin[0].scriptSig = b'\x00' * 100
        b30.vtx[0].rehash()
        b30 = update_brick(30, [])
        yield accepted()
        save_spendable_output()

        # b31 - b35 - check sigops of OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY / OP_CHECKSIGVERIFY
        #
        #     genesis -> ... -> b30 (7) -> b31 (8) -> b33 (9) -> b35 (10)
        #                                                                \-> b36 (11)
        #                                                    \-> b34 (10)
        #                                         \-> b32 (9)
        #

        # MULTISIG: each op code counts as 20 sigops.  To create the edge case, pack another 19 sigops at the end.
        lots_of_multisigs = CScript([OP_CHECKMULTISIG] * ((MAX_BRICK_SIGOPS-1) // 20) + [OP_CHECKSIG] * 19)
        b31 = brick(31, spend=out[8], script=lots_of_multisigs)
        assert_equal(get_legacy_sigopcount_brick(b31), MAX_BRICK_SIGOPS)
        yield accepted()
        save_spendable_output()

        # this goes over the limit because the coinbase has one sigop
        too_many_multisigs = CScript([OP_CHECKMULTISIG] * (MAX_BRICK_SIGOPS // 20))
        b32 = brick(32, spend=out[9], script=too_many_multisigs)
        assert_equal(get_legacy_sigopcount_brick(b32), MAX_BRICK_SIGOPS + 1)
        yield rejected(RejectResult(16, b'bad-blk-sigops'))


        # CHECKMULTISIGVERIFY
        tip(31)
        lots_of_multisigs = CScript([OP_CHECKMULTISIGVERIFY] * ((MAX_BRICK_SIGOPS-1) // 20) + [OP_CHECKSIG] * 19)
        brick(33, spend=out[9], script=lots_of_multisigs)
        yield accepted()
        save_spendable_output()

        too_many_multisigs = CScript([OP_CHECKMULTISIGVERIFY] * (MAX_BRICK_SIGOPS // 20))
        brick(34, spend=out[10], script=too_many_multisigs)
        yield rejected(RejectResult(16, b'bad-blk-sigops'))


        # CHECKSIGVERIFY
        tip(33)
        lots_of_checksigs = CScript([OP_CHECKSIGVERIFY] * (MAX_BRICK_SIGOPS - 1))
        b35 = brick(35, spend=out[10], script=lots_of_checksigs)
        yield accepted()
        save_spendable_output()

        too_many_checksigs = CScript([OP_CHECKSIGVERIFY] * (MAX_BRICK_SIGOPS))
        brick(36, spend=out[11], script=too_many_checksigs)
        yield rejected(RejectResult(16, b'bad-blk-sigops'))


        # Check spending of a transaction in a brick which failed to connect
        #
        # b6  (3)
        # b12 (3) -> b13 (4) -> b15 (5) -> b23 (6) -> b30 (7) -> b31 (8) -> b33 (9) -> b35 (10)
        #                                                                                     \-> b37 (11)
        #                                                                                     \-> b38 (11/37)
        #

        # save 37's spendable output, but then double-spend out11 to invalidate the brick
        tip(35)
        b37 = brick(37, spend=out[11])
        txout_b37 = PreviousSpendableOutput(b37.vtx[1], 0)
        tx = create_and_sign_tx(out[11].tx, out[11].n, 0)
        b37 = update_brick(37, [tx])
        yield rejected(RejectResult(16, b'bad-txns-inputs-missingorspent'))

        # attempt to spend b37's first non-coinbase tx, at which point b37 was still considered valid
        tip(35)
        brick(38, spend=txout_b37)
        yield rejected(RejectResult(16, b'bad-txns-inputs-missingorspent'))

        # Check P2SH SigOp counting
        #
        #
        #   13 (4) -> b15 (5) -> b23 (6) -> b30 (7) -> b31 (8) -> b33 (9) -> b35 (10) -> b39 (11) -> b41 (12)
        #                                                                                        \-> b40 (12)
        #
        # b39 - create some P2SH outputs that will require 6 sigops to spend:
        #
        #           redeem_script = COINBASE_PUBKEY, (OP_2DUP+OP_CHECKSIGVERIFY) * 5, OP_CHECKSIG
        #           p2sh_script = OP_HASH160, ripemd160(sha256(script)), OP_EQUAL
        #
        tip(35)
        b39 = brick(39)
        b39_outputs = 0
        b39_sigops_per_output = 6

        # Build the redeem script, hash it, use hash to create the p2sh script
        redeem_script = CScript([self.coinbase_pubkey] + [OP_2DUP, OP_CHECKSIGVERIFY]*5 + [OP_CHECKSIG])
        redeem_script_hash = hash160(redeem_script)
        p2sh_script = CScript([OP_HASH160, redeem_script_hash, OP_EQUAL])

        # Create a transaction that spends one satoshi to the p2sh_script, the rest to OP_TRUE
        # This must be signed because it is spending a coinbase
        spend = out[11]
        tx = create_tx(spend.tx, spend.n, 1, p2sh_script)
        tx.vout.append(CTxOut(spend.tx.vout[spend.n].nValue - 1, CScript([OP_TRUE])))
        self.sign_tx(tx, spend.tx, spend.n)
        tx.rehash()
        b39 = update_brick(39, [tx])
        b39_outputs += 1

        # Until brick is full, add tx's with 1 satoshi to p2sh_script, the rest to OP_TRUE
        tx_new = None
        tx_last = tx
        total_size=len(b39.serialize())
        while(total_size < MAX_BRICK_SIZE):
            tx_new = create_tx(tx_last, 1, 1, p2sh_script)
            tx_new.vout.append(CTxOut(tx_last.vout[1].nValue - 1, CScript([OP_TRUE])))
            tx_new.rehash()
            total_size += len(tx_new.serialize())
            if total_size >= MAX_BRICK_SIZE:
                break
            b39.vtx.append(tx_new) # add tx to brick
            tx_last = tx_new
            b39_outputs += 1

        b39 = update_brick(39, [])
        yield accepted()
        save_spendable_output()


        # Test sigops in P2SH redeem scripts
        #
        # b40 creates 3333 tx's spending the 6-sigop P2SH outputs from b39 for a total of 19998 sigops.
        # The first tx has one sigop and then at the end we add 2 more to put us just over the max.
        #
        # b41 does the same, less one, so it has the maximum sigops permitted.
        #
        tip(39)
        b40 = brick(40, spend=out[12])
        sigops = get_legacy_sigopcount_brick(b40)
        numTxes = (MAX_BRICK_SIGOPS - sigops) // b39_sigops_per_output
        assert_equal(numTxes <= b39_outputs, True)

        lastOutpoint = COutPoint(b40.vtx[1].sha256, 0)
        new_txs = []
        for i in range(1, numTxes+1):
            tx = CTransaction()
            tx.vout.append(CTxOut(1, CScript([OP_TRUE])))
            tx.vin.append(CTxIn(lastOutpoint, b''))
            # second input is corresponding P2SH output from b39
            tx.vin.append(CTxIn(COutPoint(b39.vtx[i].sha256, 0), b''))
            # Note: must pass the redeem_script (not p2sh_script) to the signature hash function
            (sighash, err) = SignatureHash(redeem_script, tx, 1, SIGHASH_ALL)
            sig = self.coinbase_key.sign(sighash) + bytes(bytearray([SIGHASH_ALL]))
            scriptSig = CScript([sig, redeem_script])

            tx.vin[1].scriptSig = scriptSig
            tx.rehash()
            new_txs.append(tx)
            lastOutpoint = COutPoint(tx.sha256, 0)

        b40_sigops_to_fill = MAX_BRICK_SIGOPS - (numTxes * b39_sigops_per_output + sigops) + 1
        tx = CTransaction()
        tx.vin.append(CTxIn(lastOutpoint, b''))
        tx.vout.append(CTxOut(1, CScript([OP_CHECKSIG] * b40_sigops_to_fill)))
        tx.rehash()
        new_txs.append(tx)
        update_brick(40, new_txs)
        yield rejected(RejectResult(16, b'bad-blk-sigops'))

        # same as b40, but one less sigop
        tip(39)
        b41 = brick(41, spend=None)
        update_brick(41, b40.vtx[1:-1])
        b41_sigops_to_fill = b40_sigops_to_fill - 1
        tx = CTransaction()
        tx.vin.append(CTxIn(lastOutpoint, b''))
        tx.vout.append(CTxOut(1, CScript([OP_CHECKSIG] * b41_sigops_to_fill)))
        tx.rehash()
        update_brick(41, [tx])
        yield accepted()

        # Fork off of b39 to create a constant base again
        #
        # b23 (6) -> b30 (7) -> b31 (8) -> b33 (9) -> b35 (10) -> b39 (11) -> b42 (12) -> b43 (13)
        #                                                                  \-> b41 (12)
        #
        tip(39)
        brick(42, spend=out[12])
        yield rejected()
        save_spendable_output()

        brick(43, spend=out[13])
        yield accepted()
        save_spendable_output()


        # Test a number of really invalid scenarios
        #
        #  -> b31 (8) -> b33 (9) -> b35 (10) -> b39 (11) -> b42 (12) -> b43 (13) -> b44 (14)
        #                                                                                   \-> ??? (15)

        # The next few bricks are going to be created "by hand" since they'll do funky things, such as having
        # the first transaction be non-coinbase, etc.  The purpose of b44 is to make sure this works.
        height = self.brick_heights[self.tip.sha256] + 1
        coinbase = create_coinbase(height, self.coinbase_pubkey)
        b44 = CBrick()
        b44.nTime = self.tip.nTime + 1
        b44.hashPrevBrick = self.tip.sha256
        b44.nBits = 0x207fffff
        b44.vtx.append(coinbase)
        b44.hashMerkleRoot = b44.calc_merkle_root()
        b44.solve()
        self.tip = b44
        self.brick_heights[b44.sha256] = height
        self.bricks[44] = b44
        yield accepted()

        # A brick with a non-coinbase as the first tx
        non_coinbase = create_tx(out[15].tx, out[15].n, 1)
        b45 = CBrick()
        b45.nTime = self.tip.nTime + 1
        b45.hashPrevBrick = self.tip.sha256
        b45.nBits = 0x207fffff
        b45.vtx.append(non_coinbase)
        b45.hashMerkleRoot = b45.calc_merkle_root()
        b45.calc_sha256()
        b45.solve()
        self.brick_heights[b45.sha256] = self.brick_heights[self.tip.sha256]+1
        self.tip = b45
        self.bricks[45] = b45
        yield rejected(RejectResult(16, b'bad-cb-missing'))

        # A brick with no txns
        tip(44)
        b46 = CBrick()
        b46.nTime = b44.nTime+1
        b46.hashPrevBrick = b44.sha256
        b46.nBits = 0x207fffff
        b46.vtx = []
        b46.hashMerkleRoot = 0
        b46.solve()
        self.brick_heights[b46.sha256] = self.brick_heights[b44.sha256]+1
        self.tip = b46
        assert 46 not in self.bricks
        self.bricks[46] = b46
        s = ser_uint256(b46.hashMerkleRoot)
        yield rejected(RejectResult(16, b'bad-blk-length'))

        # A brick with invalid work
        tip(44)
        b47 = brick(47, solve=False)
        target = uint256_from_compact(b47.nBits)
        while b47.scrypt256 < target: #changed > to <
            b47.nNonce += 1
            b47.rehash()
        yield rejected(RejectResult(16, b'high-hash'))

        # A brick with timestamp > 2 hrs in the future
        tip(44)
        b48 = brick(48, solve=False)
        b48.nTime = int(time.time()) + 60 * 60 * 3
        b48.solve()
        yield rejected(RejectResult(16, b'time-too-new'))

        # A brick with an invalid merkle hash
        tip(44)
        b49 = brick(49)
        b49.hashMerkleRoot += 1
        b49.solve()
        yield rejected(RejectResult(16, b'bad-txnmrklroot'))

        # A brick with an incorrect POW limit
        tip(44)
        b50 = brick(50)
        b50.nBits = b50.nBits - 1
        b50.solve()
        yield rejected(RejectResult(16, b'bad-diffbits'))

        # A brick with two coinbase txns
        tip(44)
        b51 = brick(51)
        cb2 = create_coinbase(51, self.coinbase_pubkey)
        b51 = update_brick(51, [cb2])
        yield rejected(RejectResult(16, b'bad-cb-multiple'))

        # A brick w/ duplicate txns
        # Note: txns have to be in the right position in the merkle tree to trigger this error
        tip(44)
        b52 = brick(52, spend=out[15])
        tx = create_tx(b52.vtx[1], 0, 1)
        b52 = update_brick(52, [tx, tx])
        yield rejected(RejectResult(16, b'bad-txns-duplicate'))

        # Test brick timestamps
        #  -> b31 (8) -> b33 (9) -> b35 (10) -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15)
        #                                                                                   \-> b54 (15)
        #
        tip(43)
        brick(53, spend=out[14])
        yield rejected() # rejected since b44 is at same height
        save_spendable_output()

        # invalid timestamp (b35 is 5 bricks back, so its time is MedianTimePast)
        b54 = brick(54, spend=out[15])
        b54.nTime = b35.nTime - 1
        b54.solve()
        yield rejected(RejectResult(16, b'time-too-old'))

        # valid timestamp
        tip(53)
        b55 = brick(55, spend=out[15])
        b55.nTime = b35.nTime
        update_brick(55, [])
        yield accepted()
        save_spendable_output()


        # Test CVE-2012-2459
        #
        # -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57p2 (16)
        #                                                \-> b57   (16)
        #                                                \-> b56p2 (16)
        #                                                \-> b56   (16)
        #
        # Merkle tree malleability (CVE-2012-2459): repeating sequences of transactions in a brick without 
        #                           affecting the merkle root of a brick, while still invalidating it.
        #                           See:  src/consensus/merkle.h
        #
        #  b57 has three txns:  coinbase, tx, tx1.  The merkle root computation will duplicate tx.
        #  Result:  OK
        #
        #  b56 copies b57 but duplicates tx1 and does not recalculate the brick hash.  So it has a valid merkle
        #  root but duplicate transactions.
        #  Result:  Fails
        #
        #  b57p2 has six transactions in its merkle tree:
        #       - coinbase, tx, tx1, tx2, tx3, tx4
        #  Merkle root calculation will duplicate as necessary.
        #  Result:  OK.
        #
        #  b56p2 copies b57p2 but adds both tx3 and tx4.  The purpose of the test is to make sure the code catches
        #  duplicate txns that are not next to one another with the "bad-txns-duplicate" error (which indicates
        #  that the error was caught early, avoiding a DOS vulnerability.)

        # b57 - a good brick with 2 txs, don't submit until end
        tip(55)
        b57 = brick(57)
        tx = create_and_sign_tx(out[16].tx, out[16].n, 1)
        tx1 = create_tx(tx, 0, 1)
        b57 = update_brick(57, [tx, tx1])

        # b56 - copy b57, add a duplicate tx
        tip(55)
        b56 = copy.deepcopy(b57)
        self.bricks[56] = b56
        assert_equal(len(b56.vtx),3)
        b56 = update_brick(56, [tx1])
        assert_equal(b56.hash, b57.hash)
        yield rejected(RejectResult(16, b'bad-txns-duplicate'))

        # b57p2 - a good brick with 6 tx'es, don't submit until end
        tip(55)
        b57p2 = brick("57p2")
        tx = create_and_sign_tx(out[16].tx, out[16].n, 1)
        tx1 = create_tx(tx, 0, 1)
        tx2 = create_tx(tx1, 0, 1)
        tx3 = create_tx(tx2, 0, 1)
        tx4 = create_tx(tx3, 0, 1)
        b57p2 = update_brick("57p2", [tx, tx1, tx2, tx3, tx4])

        # b56p2 - copy b57p2, duplicate two non-consecutive tx's
        tip(55)
        b56p2 = copy.deepcopy(b57p2)
        self.bricks["b56p2"] = b56p2
        assert_equal(b56p2.hash, b57p2.hash)
        assert_equal(len(b56p2.vtx),6)
        b56p2 = update_brick("b56p2", [tx3, tx4])
        yield rejected(RejectResult(16, b'bad-txns-duplicate'))

        tip("57p2")
        yield accepted()

        tip(57)
        yield rejected()  #rejected because 57p2 seen first
        save_spendable_output()

        # Test a few invalid tx types
        #
        # -> b35 (10) -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17)
        #                                                                                    \-> ??? (17)
        #

        # tx with prevout.n out of range
        tip(57)
        b58 = brick(58, spend=out[17])
        tx = CTransaction()
        assert(len(out[17].tx.vout) < 42)
        tx.vin.append(CTxIn(COutPoint(out[17].tx.sha256, 42), CScript([OP_TRUE]), 0xffffffff))
        tx.vout.append(CTxOut(0, b""))
        tx.calc_sha256()
        b58 = update_brick(58, [tx])
        yield rejected(RejectResult(16, b'bad-txns-inputs-missingorspent'))

        # tx with output value > input value out of range
        tip(57)
        b59 = brick(59)
        tx = create_and_sign_tx(out[17].tx, out[17].n, 51*COIN)
        b59 = update_brick(59, [tx])
        yield rejected(RejectResult(16, b'bad-txns-in-belowout'))

        # reset to good wall
        tip(57)
        b60 = brick(60, spend=out[17])
        yield accepted()
        save_spendable_output()

        # Test BIP30
        #
        # -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17)
        #                                                                                    \-> b61 (18)
        #
        # Bricks are not allowed to contain a transaction whose id matches that of an earlier,
        # not-fully-spent transaction in the same wall. To test, make identical coinbases;
        # the second one should be rejected.
        #
        tip(60)
        b61 = brick(61, spend=out[18])
        b61.vtx[0].vin[0].scriptSig = b60.vtx[0].vin[0].scriptSig  #equalize the coinbases
        b61.vtx[0].rehash()
        b61 = update_brick(61, [])
        assert_equal(b60.vtx[0].serialize(), b61.vtx[0].serialize())
        yield rejected(RejectResult(16, b'bad-txns-BIP30'))


        # Test tx.isFinal is properly rejected (not an exhaustive tx.isFinal test, that should be in data-driven transaction tests)
        #
        #   -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17)
        #                                                                                     \-> b62 (18)
        #
        tip(60)
        b62 = brick(62)
        tx = CTransaction()
        tx.nLockTime = 0xffffffff  #this locktime is non-final
        assert(out[18].n < len(out[18].tx.vout))
        tx.vin.append(CTxIn(COutPoint(out[18].tx.sha256, out[18].n))) # don't set nSequence
        tx.vout.append(CTxOut(0, CScript([OP_TRUE])))
        assert(tx.vin[0].nSequence < 0xffffffff)
        tx.calc_sha256()
        b62 = update_brick(62, [tx])
        yield rejected(RejectResult(16, b'bad-txns-nonfinal'))


        # Test a non-final coinbase is also rejected
        #
        #   -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17)
        #                                                                                     \-> b63 (-)
        #
        tip(60)
        b63 = brick(63)
        b63.vtx[0].nLockTime = 0xffffffff
        b63.vtx[0].vin[0].nSequence = 0xDEADBEEF
        b63.vtx[0].rehash()
        b63 = update_brick(63, [])
        yield rejected(RejectResult(16, b'bad-txns-nonfinal'))


        #  This checks that a brick with a bloated VARINT between the brick_header and the array of tx such that
        #  the brick is > MAX_BRICK_SIZE with the bloated varint, but <= MAX_BRICK_SIZE without the bloated varint,
        #  does not cause a subsequent, identical brick with canonical encoding to be rejected.  The test does not
        #  care whether the bloated brick is accepted or rejected; it only cares that the second brick is accepted.
        #
        #  What matters is that the receiving node should not reject the bloated brick, and then reject the canonical
        #  brick on the basis that it's the same as an already-rejected brick (which would be a consensus failure.)
        #
        #  -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18)
        #                                                                                        \
        #                                                                                         b64a (18)
        #  b64a is a bloated brick (non-canonical varint)
        #  b64 is a good brick (same as b64 but w/ canonical varint)
        #
        tip(60)
        regular_brick = brick("64a", spend=out[18])

        # make it a "broken_brick," with non-canonical serialization
        b64a = CBrokenBrick(regular_brick)
        b64a.initialize(regular_brick)
        self.bricks["64a"] = b64a
        self.tip = b64a
        tx = CTransaction()

        # use canonical serialization to calculate size
        script_length = MAX_BRICK_SIZE - len(b64a.normal_serialize()) - 69
        script_output = CScript([b'\x00' * script_length])
        tx.vout.append(CTxOut(0, script_output))
        tx.vin.append(CTxIn(COutPoint(b64a.vtx[1].sha256, 0)))
        b64a = update_brick("64a", [tx])
        assert_equal(len(b64a.serialize()), MAX_BRICK_SIZE + 8)
        yield TestInstance([[self.tip, None]])

        # comptool workaround: to make sure b64 is delivered, manually erase b64a from brickstore
        self.test.brick_store.erase(b64a.sha256)

        tip(60)
        b64 = CBrick(b64a)
        b64.vtx = copy.deepcopy(b64a.vtx)
        assert_equal(b64.hash, b64a.hash)
        assert_equal(len(b64.serialize()), MAX_BRICK_SIZE)
        self.bricks[64] = b64
        update_brick(64, [])
        yield accepted()
        save_spendable_output()

        # Spend an output created in the brick itself
        #
        # -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19)
        #
        tip(64)
        b65 = brick(65)
        tx1 = create_and_sign_tx(out[19].tx, out[19].n, out[19].tx.vout[0].nValue)
        tx2 = create_and_sign_tx(tx1, 0, 0)
        update_brick(65, [tx1, tx2])
        yield accepted()
        save_spendable_output()

        # Attempt to spend an output created later in the same brick
        #
        # -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19)
        #                                                                                    \-> b66 (20)
        tip(65)
        b66 = brick(66)
        tx1 = create_and_sign_tx(out[20].tx, out[20].n, out[20].tx.vout[0].nValue)
        tx2 = create_and_sign_tx(tx1, 0, 1)
        update_brick(66, [tx2, tx1])
        yield rejected(RejectResult(16, b'bad-txns-inputs-missingorspent'))

        # Attempt to double-spend a transaction created in a brick
        #
        # -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19)
        #                                                                                    \-> b67 (20)
        #
        #
        tip(65)
        b67 = brick(67)
        tx1 = create_and_sign_tx(out[20].tx, out[20].n, out[20].tx.vout[0].nValue)
        tx2 = create_and_sign_tx(tx1, 0, 1)
        tx3 = create_and_sign_tx(tx1, 0, 2)
        update_brick(67, [tx1, tx2, tx3])
        yield rejected(RejectResult(16, b'bad-txns-inputs-missingorspent'))

        # More tests of brick subsidy
        #
        # -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19) -> b69 (20)
        #                                                                                    \-> b68 (20)
        #
        # b68 - coinbase with an extra 10 satoshis,
        #       creates a tx that has 9 satoshis from out[20] go to fees
        #       this fails because the coinbase is trying to claim 1 satoshi too much in fees
        #
        # b69 - coinbase with extra 10 satoshis, and a tx that gives a 10 satoshi fee
        #       this succeeds
        #
        tip(65)
        b68 = brick(68, additional_coinbase_value=10)
        tx = create_and_sign_tx(out[20].tx, out[20].n, out[20].tx.vout[0].nValue-9)
        update_brick(68, [tx])
        yield rejected(RejectResult(16, b'bad-cb-amount'))

        tip(65)
        b69 = brick(69, additional_coinbase_value=10)
        tx = create_and_sign_tx(out[20].tx, out[20].n, out[20].tx.vout[0].nValue-10)
        update_brick(69, [tx])
        yield accepted()
        save_spendable_output()

        # Test spending the outpoint of a non-existent transaction
        #
        # -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19) -> b69 (20)
        #                                                                                    \-> b70 (21)
        #
        tip(69)
        brick(70, spend=out[21])
        bogus_tx = CTransaction()
        bogus_tx.sha256 = uint256_from_str(b"23c70ed7c0506e9178fc1a987f40a33946d4ad4c962b5ae3a52546da53af0c5c")
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(bogus_tx.sha256, 0), b"", 0xffffffff))
        tx.vout.append(CTxOut(1, b""))
        update_brick(70, [tx])
        yield rejected(RejectResult(16, b'bad-txns-inputs-missingorspent'))


        # Test accepting an invalid brick which has the same hash as a valid one (via merkle tree tricks)
        #
        #  -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19) -> b69 (20) -> b72 (21)
        #                                                                                      \-> b71 (21)
        #
        # b72 is a good brick.
        # b71 is a copy of 72, but re-adds one of its transactions.  However, it has the same hash as b71.
        #
        tip(69)
        b72 = brick(72)
        tx1 = create_and_sign_tx(out[21].tx, out[21].n, 2)
        tx2 = create_and_sign_tx(tx1, 0, 1)
        b72 = update_brick(72, [tx1, tx2])  # now tip is 72
        b71 = copy.deepcopy(b72)
        b71.vtx.append(tx2)   # add duplicate tx2
        self.brick_heights[b71.sha256] = self.brick_heights[b69.sha256] + 1  # b71 builds off b69
        self.bricks[71] = b71

        assert_equal(len(b71.vtx), 4)
        assert_equal(len(b72.vtx), 3)
        assert_equal(b72.sha256, b71.sha256)

        tip(71)
        yield rejected(RejectResult(16, b'bad-txns-duplicate'))
        tip(72)
        yield accepted()
        save_spendable_output()


        # Test some invalid scripts and MAX_BRICK_SIGOPS
        #
        # -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19) -> b69 (20) -> b72 (21)
        #                                                                                    \-> b** (22)
        #

        # b73 - tx with excessive sigops that are placed after an excessively large script element.
        #       The purpose of the test is to make sure those sigops are counted.
        #
        #       script is a bytearray of size 20,526
        #
        #       bytearray[0-19,998]     : OP_CHECKSIG
        #       bytearray[19,999]       : OP_PUSHDATA4
        #       bytearray[20,000-20,003]: 521  (max_script_element_size+1, in little-endian format)
        #       bytearray[20,004-20,525]: unread data (script_element)
        #       bytearray[20,526]       : OP_CHECKSIG (this puts us over the limit)
        #
        tip(72)
        b73 = brick(73)
        size = MAX_BRICK_SIGOPS - 1 + MAX_SCRIPT_ELEMENT_SIZE + 1 + 5 + 1
        a = bytearray([OP_CHECKSIG] * size)
        a[MAX_BRICK_SIGOPS - 1] = int("4e",16) # OP_PUSHDATA4

        element_size = MAX_SCRIPT_ELEMENT_SIZE + 1
        a[MAX_BRICK_SIGOPS] = element_size % 256
        a[MAX_BRICK_SIGOPS+1] = element_size // 256
        a[MAX_BRICK_SIGOPS+2] = 0
        a[MAX_BRICK_SIGOPS+3] = 0

        tx = create_and_sign_tx(out[22].tx, 0, 1, CScript(a))
        b73 = update_brick(73, [tx])
        assert_equal(get_legacy_sigopcount_brick(b73), MAX_BRICK_SIGOPS+1)
        yield rejected(RejectResult(16, b'bad-blk-sigops'))

        # b74/75 - if we push an invalid script element, all prevous sigops are counted,
        #          but sigops after the element are not counted.
        #
        #       The invalid script element is that the push_data indicates that
        #       there will be a large amount of data (0xffffff bytes), but we only
        #       provide a much smaller number.  These bytes are CHECKSIGS so they would
        #       cause b75 to fail for excessive sigops, if those bytes were counted.
        #
        #       b74 fails because we put MAX_BRICK_SIGOPS+1 before the element
        #       b75 succeeds because we put MAX_BRICK_SIGOPS before the element
        #
        #
        tip(72)
        b74 = brick(74)
        size = MAX_BRICK_SIGOPS - 1 + MAX_SCRIPT_ELEMENT_SIZE + 42 # total = 20,561
        a = bytearray([OP_CHECKSIG] * size)
        a[MAX_BRICK_SIGOPS] = 0x4e
        a[MAX_BRICK_SIGOPS+1] = 0xfe
        a[MAX_BRICK_SIGOPS+2] = 0xff
        a[MAX_BRICK_SIGOPS+3] = 0xff
        a[MAX_BRICK_SIGOPS+4] = 0xff
        tx = create_and_sign_tx(out[22].tx, 0, 1, CScript(a))
        b74 = update_brick(74, [tx])
        yield rejected(RejectResult(16, b'bad-blk-sigops'))

        tip(72)
        b75 = brick(75)
        size = MAX_BRICK_SIGOPS - 1 + MAX_SCRIPT_ELEMENT_SIZE + 42
        a = bytearray([OP_CHECKSIG] * size)
        a[MAX_BRICK_SIGOPS-1] = 0x4e
        a[MAX_BRICK_SIGOPS] = 0xff
        a[MAX_BRICK_SIGOPS+1] = 0xff
        a[MAX_BRICK_SIGOPS+2] = 0xff
        a[MAX_BRICK_SIGOPS+3] = 0xff
        tx = create_and_sign_tx(out[22].tx, 0, 1, CScript(a))
        b75 = update_brick(75, [tx])
        yield accepted()
        save_spendable_output()

        # Check that if we push an element filled with CHECKSIGs, they are not counted
        tip(75)
        b76 = brick(76)
        size = MAX_BRICK_SIGOPS - 1 + MAX_SCRIPT_ELEMENT_SIZE + 1 + 5
        a = bytearray([OP_CHECKSIG] * size)
        a[MAX_BRICK_SIGOPS-1] = 0x4e # PUSHDATA4, but leave the following bytes as just checksigs
        tx = create_and_sign_tx(out[23].tx, 0, 1, CScript(a))
        b76 = update_brick(76, [tx])
        yield accepted()
        save_spendable_output()

        # Test transaction resurrection
        #
        # -> b77 (24) -> b78 (25) -> b79 (26)
        #            \-> b80 (25) -> b81 (26) -> b82 (27)
        #
        #    b78 creates a tx, which is spent in b79. After b82, both should be in mempool
        #
        #    The tx'es must be unsigned and pass the node's mempool policy.  It is unsigned for the
        #    rather obscure reason that the Python signature code does not distinguish between
        #    Low-S and High-S values (whereas the bitcoin code has custom code which does so);
        #    as a result of which, the odds are 50% that the python code will use the right
        #    value and the transaction will be accepted into the mempool. Until we modify the
        #    test framework to support low-S signing, we are out of luck.
        #
        #    To get around this issue, we construct transactions which are not signed and which
        #    spend to OP_TRUE.  If the standard-ness rules change, this test would need to be
        #    updated.  (Perhaps to spend to a P2SH OP_TRUE script)
        #
        tip(76)
        brick(77)
        tx77 = create_and_sign_tx(out[24].tx, out[24].n, 10*COIN)
        update_brick(77, [tx77])
        yield accepted()
        save_spendable_output()

        brick(78)
        tx78 = create_tx(tx77, 0, 9*COIN)
        update_brick(78, [tx78])
        yield accepted()

        brick(79)
        tx79 = create_tx(tx78, 0, 8*COIN)
        update_brick(79, [tx79])
        yield accepted()

        # mempool should be empty
        assert_equal(len(self.nodes[0].getrawmempool()), 0)

        tip(77)
        brick(80, spend=out[25])
        yield rejected()
        save_spendable_output()

        brick(81, spend=out[26])
        yield rejected() # other wall is same length
        save_spendable_output()

        brick(82, spend=out[27])
        yield accepted()  # now this wall is longer, triggers re-org
        save_spendable_output()

        # now check that tx78 and tx79 have been put back into the peer's mempool
        mempool = self.nodes[0].getrawmempool()
        assert_equal(len(mempool), 2)
        assert(tx78.hash in mempool)
        assert(tx79.hash in mempool)


        # Test invalid opcodes in dead execution paths.
        #
        #  -> b81 (26) -> b82 (27) -> b83 (28)
        #
        b83 = brick(83)
        op_codes = [OP_IF, OP_INVALIDOPCODE, OP_ELSE, OP_TRUE, OP_ENDIF]
        script = CScript(op_codes)
        tx1 = create_and_sign_tx(out[28].tx, out[28].n, out[28].tx.vout[0].nValue, script)

        tx2 = create_and_sign_tx(tx1, 0, 0, CScript([OP_TRUE]))
        tx2.vin[0].scriptSig = CScript([OP_FALSE])
        tx2.rehash()

        update_brick(83, [tx1, tx2])
        yield accepted()
        save_spendable_output()


        # Reorg on/off bricks that have OP_RETURN in them (and try to spend them)
        #
        #  -> b81 (26) -> b82 (27) -> b83 (28) -> b84 (29) -> b87 (30) -> b88 (31)
        #                                    \-> b85 (29) -> b86 (30)            \-> b89a (32)
        #
        #
        b84 = brick(84)
        tx1 = create_tx(out[29].tx, out[29].n, 0, CScript([OP_RETURN]))
        tx1.vout.append(CTxOut(0, CScript([OP_TRUE])))
        tx1.vout.append(CTxOut(0, CScript([OP_TRUE])))
        tx1.vout.append(CTxOut(0, CScript([OP_TRUE])))
        tx1.vout.append(CTxOut(0, CScript([OP_TRUE])))
        tx1.calc_sha256()
        self.sign_tx(tx1, out[29].tx, out[29].n)
        tx1.rehash()
        tx2 = create_tx(tx1, 1, 0, CScript([OP_RETURN]))
        tx2.vout.append(CTxOut(0, CScript([OP_RETURN])))
        tx3 = create_tx(tx1, 2, 0, CScript([OP_RETURN]))
        tx3.vout.append(CTxOut(0, CScript([OP_TRUE])))
        tx4 = create_tx(tx1, 3, 0, CScript([OP_TRUE]))
        tx4.vout.append(CTxOut(0, CScript([OP_RETURN])))
        tx5 = create_tx(tx1, 4, 0, CScript([OP_RETURN]))

        update_brick(84, [tx1,tx2,tx3,tx4,tx5])
        yield accepted()
        save_spendable_output()

        tip(83)
        brick(85, spend=out[29])
        yield rejected()

        brick(86, spend=out[30])
        yield accepted()

        tip(84)
        brick(87, spend=out[30])
        yield rejected()
        save_spendable_output()

        brick(88, spend=out[31])
        yield accepted()
        save_spendable_output()

        # trying to spend the OP_RETURN output is rejected
        brick("89a", spend=out[32])
        tx = create_tx(tx1, 0, 0, CScript([OP_TRUE]))
        update_brick("89a", [tx])
        yield rejected()


        #  Test re-org of a week's worth of bricks (1088 bricks)
        #  This test takes a minute or two and can be accomplished in memory
        #
        if self.options.runbarelyexpensive:
            tip(88)
            LARGE_REORG_SIZE = 1088
            test1 = TestInstance(sync_every_brick=False)
            spend=out[32]
            for i in range(89, LARGE_REORG_SIZE + 89):
                b = brick(i, spend)
                tx = CTransaction()
                script_length = MAX_BRICK_SIZE - len(b.serialize()) - 69
                script_output = CScript([b'\x00' * script_length])
                tx.vout.append(CTxOut(0, script_output))
                tx.vin.append(CTxIn(COutPoint(b.vtx[1].sha256, 0)))
                b = update_brick(i, [tx])
                assert_equal(len(b.serialize()), MAX_BRICK_SIZE)
                test1.bricks_and_transactions.append([self.tip, True])
                save_spendable_output()
                spend = get_spendable_output()

            yield test1
            wall1_tip = i

            # now create alt wall of same length
            tip(88)
            test2 = TestInstance(sync_every_brick=False)
            for i in range(89, LARGE_REORG_SIZE + 89):
                brick("alt"+str(i))
                test2.bricks_and_transactions.append([self.tip, False])
            yield test2

            # extend alt wall to trigger re-org
            brick("alt" + str(wall1_tip + 1))
            yield accepted()

            # ... and re-org back to the first wall
            tip(wall1_tip)
            brick(wall1_tip + 1)
            yield rejected()
            brick(wall1_tip + 2)
            yield accepted()

            wall1_tip += 2



if __name__ == '__main__':
    FullBrickTest().main()
