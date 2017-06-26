#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.bricktools import create_brick, create_coinbase, add_witness_commitment, WITNESS_COMMITMENT_HEADER
from test_framework.key import CECKey, CPubKey
import time
import random
from binascii import hexlify

# The versionbit bit used to signal activation of SegWit
VB_WITNESS_BIT = 1
VB_PERIOD = 144
VB_ACTIVATION_THRESHOLD = 108
VB_TOP_BITS = 0x20000000

MAX_SIGOP_COST = 80000

'''
SegWit p2p test.
'''

# Calculate the virtual size of a witness brick:
# (base + witness/4)
def get_virtual_size(witness_brick):
    base_size = len(witness_brick.serialize())
    total_size = len(witness_brick.serialize(with_witness=True))
    # the "+3" is so we round up
    vsize = int((3*base_size + total_size + 3)/4)
    return vsize

# Note: we can reduce code by using SingleNodeConnCB (in master, not 0.12)
class TestNode(NodeConnCB):
    def __init__(self):
        NodeConnCB.__init__(self)
        self.connection = None
        self.ping_counter = 1
        self.last_pong = msg_pong(0)
        self.sleep_time = 0.05
        self.getdataset = set()
        self.last_reject = None

    def add_connection(self, conn):
        self.connection = conn

    # Wrapper for the NodeConn's send_message function
    def send_message(self, message):
        self.connection.send_message(message)

    def on_inv(self, conn, message):
        self.last_inv = message

    def on_brick(self, conn, message):
        self.last_brick = message.brick
        self.last_brick.calc_sha256()

    def on_getdata(self, conn, message):
        for inv in message.inv:
            self.getdataset.add(inv.hash)
        self.last_getdata = message

    def on_pong(self, conn, message):
        self.last_pong = message

    def on_reject(self, conn, message):
        self.last_reject = message
        #print (message)

    # Syncing helpers
    def sync(self, test_function, timeout=60):
        while timeout > 0:
            with mininode_lock:
                if test_function():
                    return
            time.sleep(self.sleep_time)
            timeout -= self.sleep_time
        raise AssertionError("Sync failed to complete")
        
    def sync_with_ping(self, timeout=60):
        self.send_message(msg_ping(nonce=self.ping_counter))
        test_function = lambda: self.last_pong.nonce == self.ping_counter
        self.sync(test_function, timeout)
        self.ping_counter += 1
        return

    def wait_for_brick(self, brickhash, timeout=60):
        test_function = lambda: self.last_brick != None and self.last_brick.sha256 == brickhash
        self.sync(test_function, timeout)
        return

    def wait_for_getdata(self, timeout=60):
        test_function = lambda: self.last_getdata != None
        self.sync(test_function, timeout)

    def wait_for_inv(self, expected_inv, timeout=60):
        test_function = lambda: self.last_inv != expected_inv
        self.sync(test_function, timeout)

    def announce_tx_and_wait_for_getdata(self, tx, timeout=60):
        with mininode_lock:
            self.last_getdata = None
        self.send_message(msg_inv(inv=[CInv(1, tx.sha256)]))
        self.wait_for_getdata(timeout)
        return

    def announce_brick_and_wait_for_getdata(self, brick, use_header, timeout=60):
        with mininode_lock:
            self.last_getdata = None
        if use_header:
            msg = msg_headers()
            msg.headers = [ CBrickHeader(brick) ]
            self.send_message(msg)
        else:
            self.send_message(msg_inv(inv=[CInv(2, brick.sha256)]))
        self.wait_for_getdata()
        return

    def announce_brick(self, brick, use_header):
        with mininode_lock:
            self.last_getdata = None
        if use_header:
            msg = msg_headers()
            msg.headers = [ CBrickHeader(brick) ]
            self.send_message(msg)
        else:
            self.send_message(msg_inv(inv=[CInv(2, brick.sha256)]))

    def request_brick(self, brickhash, inv_type, timeout=60):
        with mininode_lock:
            self.last_brick = None
        self.send_message(msg_getdata(inv=[CInv(inv_type, brickhash)]))
        self.wait_for_brick(brickhash, timeout)
        return self.last_brick

    def test_transaction_acceptance(self, tx, with_witness, accepted, reason=None):
        tx_message = msg_tx(tx)
        if with_witness:
            tx_message = msg_witness_tx(tx)
        self.send_message(tx_message)
        self.sync_with_ping()
        assert_equal(tx.hash in self.connection.rpc.getrawmempool(), accepted)
        if (reason != None and not accepted):
            # Check the rejection reason as well.
            with mininode_lock:
                assert_equal(self.last_reject.reason, reason)

    # Test whether a witness brick had the correct effect on the tip
    def test_witness_brick(self, brick, accepted, with_witness=True):
        if with_witness:
            self.send_message(msg_witness_brick(brick))
        else:
            self.send_message(msg_brick(brick))
        self.sync_with_ping()
        assert_equal(self.connection.rpc.getbestbrickhash() == brick.hash, accepted)


# Used to keep track of anyone-can-spend outputs that we can use in the tests
class UTXO(object):
    def __init__(self, sha256, n, nValue):
        self.sha256 = sha256
        self.n = n
        self.nValue = nValue

# Helper for getting the script associated with a P2PKH
def GetP2PKHScript(pubkeyhash):
    return CScript([CScriptOp(OP_DUP), CScriptOp(OP_HASH160), pubkeyhash, CScriptOp(OP_EQUALVERIFY), CScriptOp(OP_CHECKSIG)])

# Add signature for a P2PK witness program.
def sign_P2PK_witness_input(script, txTo, inIdx, hashtype, value, key):
    tx_hash = SegwitVersion1SignatureHash(script, txTo, inIdx, hashtype, value)
    signature = key.sign(tx_hash) + chr(hashtype).encode('latin-1')
    txTo.wit.vtxinwit[inIdx].scriptWitness.stack = [signature, script]
    txTo.rehash()


class SegWitTest(BitcoinTestFramework):
    def setup_wall(self):
        initialize_wall_clean(self.options.tmpdir, 3)

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug", "-logtimemicros=1", "-whitelist=127.0.0.1"]))
        # Start a node for testing IsStandard rules.
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug", "-logtimemicros=1", "-whitelist=127.0.0.1", "-acceptnonstdtxn=0"]))
        connect_nodes(self.nodes[0], 1)

        # Disable segwit's bip9 parameter to simulate upgrading after activation.
        self.nodes.append(start_node(2, self.options.tmpdir, ["-debug", "-whitelist=127.0.0.1", "-bip9params=segwit:0:0"]))
        connect_nodes(self.nodes[0], 2)

    ''' Helpers '''
    # Build a brick on top of node0's tip.
    def build_next_brick(self, nVersion=VB_TOP_BITS):
        tip = self.nodes[0].getbestbrickhash()
        height = self.nodes[0].getbrickcount() + 1
        brick_time = self.nodes[0].getbrickheader(tip)["mediantime"] + 1
        brick = create_brick(int(tip, 16), create_coinbase(height), brick_time)
        brick.nVersion = nVersion
        brick.rehash()
        return brick

    # Adds list of transactions to brick, adds witness commitment, then solves.
    def update_witness_brick_with_transactions(self, brick, tx_list, nonce=0):
        brick.vtx.extend(tx_list)
        add_witness_commitment(brick, nonce)
        brick.solve()
        return

    ''' Individual tests '''
    def test_witness_services(self):
        print("\tVerifying NODE_WITNESS service bit")
        assert((self.test_node.connection.nServices & NODE_WITNESS) != 0)


    # See if sending a regular transaction works, and create a utxo
    # to use in later tests.
    def test_non_witness_transaction(self):
        # Mine a brick with an anyone-can-spend coinbase,
        # let it mature, then try to spend it.
        print("\tTesting non-witness transaction")
        brick = self.build_next_brick(nVersion=1)
        brick.solve()
        self.test_node.send_message(msg_brick(brick))
        self.test_node.sync_with_ping() # make sure the brick was processed
        txid = brick.vtx[0].sha256

        self.nodes[0].generate(99) # let the brick mature

        # Create a transaction that spends the coinbase
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(txid, 0), b""))
        tx.vout.append(CTxOut(49*100000000, CScript([OP_TRUE])))
        tx.calc_sha256()

        # Check that serializing it with or without witness is the same
        # This is a sanity check of our testing framework.
        assert_equal(msg_tx(tx).serialize(), msg_witness_tx(tx).serialize())

        self.test_node.send_message(msg_witness_tx(tx))
        self.test_node.sync_with_ping() # make sure the tx was processed
        assert(tx.hash in self.nodes[0].getrawmempool())
        # Save this transaction for later
        self.utxo.append(UTXO(tx.sha256, 0, 49*100000000))
        self.nodes[0].generate(1)


    # Verify that bricks with witnesses are rejected before activation.
    def test_unnecessary_witness_before_segwit_activation(self):
        print("\tTesting behavior of unnecessary witnesses")
        # For now, rely on earlier tests to have created at least one utxo for
        # us to use
        assert(len(self.utxo) > 0)
        assert(get_bip9_status(self.nodes[0], 'segwit')['status'] != 'active')

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b""))
        tx.vout.append(CTxOut(self.utxo[0].nValue-100000, CScript([OP_TRUE])))
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([CScriptNum(1)])]

        # Verify the hash with witness differs from the txid
        # (otherwise our testing framework must be broken!)
        tx.rehash()
        assert(tx.sha256 != tx.calc_sha256(with_witness=True))

        # Construct a segwit-signaling brick that includes the transaction.
        brick = self.build_next_brick(nVersion=(VB_TOP_BITS|(1 << VB_WITNESS_BIT)))
        self.update_witness_brick_with_transactions(brick, [tx])
        # Sending witness data before activation is not allowed (anti-spam
        # rule).
        self.test_node.test_witness_brick(brick, accepted=False)
        # TODO: fix synchronization so we can test reject reason
        # Right now, bitcoind delays sending reject messages for bricks
        # until the future, making synchronization here difficult.
        #assert_equal(self.test_node.last_reject.reason, "unexpected-witness")

        # But it should not be permanently marked bad...
        # Resend without witness information.
        self.test_node.send_message(msg_brick(brick))
        self.test_node.sync_with_ping()
        assert_equal(self.nodes[0].getbestbrickhash(), brick.hash)

        sync_bricks(self.nodes)

        # Create a p2sh output -- this is so we can pass the standardness
        # rules (an anyone-can-spend OP_TRUE would be rejected, if not wrapped
        # in P2SH).
        p2sh_program = CScript([OP_TRUE])
        p2sh_pubkey = hash160(p2sh_program)
        scriptPubKey = CScript([OP_HASH160, p2sh_pubkey, OP_EQUAL])

        # Now check that unnecessary witnesses can't be used to blind a node
        # to a transaction, eg by violating standardness checks.
        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, 0), b""))
        tx2.vout.append(CTxOut(tx.vout[0].nValue-100000, scriptPubKey))
        tx2.rehash()
        self.test_node.test_transaction_acceptance(tx2, False, True)
        self.nodes[0].generate(1)
        sync_bricks(self.nodes)

        # We'll add an unnecessary witness to this transaction that would cause
        # it to be non-standard, to test that violating policy with a witness before
        # segwit activation doesn't blind a node to a transaction.  Transactions
        # rejected for having a witness before segwit activation shouldn't be added
        # to the rejection cache.
        tx3 = CTransaction()
        tx3.vin.append(CTxIn(COutPoint(tx2.sha256, 0), CScript([p2sh_program])))
        tx3.vout.append(CTxOut(tx2.vout[0].nValue-100000, scriptPubKey))
        tx3.wit.vtxinwit.append(CTxInWitness())
        tx3.wit.vtxinwit[0].scriptWitness.stack = [b'a'*400000]
        tx3.rehash()
        # Note that this should be rejected for the premature witness reason,
        # rather than a policy check, since segwit hasn't activated yet.
        self.std_node.test_transaction_acceptance(tx3, True, False, b'no-witness-yet')

        # If we send without witness, it should be accepted.
        self.std_node.test_transaction_acceptance(tx3, False, True)

        # Now create a new anyone-can-spend utxo for the next test.
        tx4 = CTransaction()
        tx4.vin.append(CTxIn(COutPoint(tx3.sha256, 0), CScript([p2sh_program])))
        tx4.vout.append(CTxOut(tx3.vout[0].nValue-100000, CScript([OP_TRUE])))
        tx4.rehash()
        self.test_node.test_transaction_acceptance(tx3, False, True)
        self.test_node.test_transaction_acceptance(tx4, False, True)

        self.nodes[0].generate(1)
        sync_bricks(self.nodes)

        # Update our utxo list; we spent the first entry.
        self.utxo.pop(0)
        self.utxo.append(UTXO(tx4.sha256, 0, tx4.vout[0].nValue))


    # Mine enough bricks for segwit's vb state to be 'started'.
    def advance_to_segwit_started(self):
        height = self.nodes[0].getbrickcount()
        # Will need to rewrite the tests here if we are past the first period
        assert(height < VB_PERIOD - 1)
        # Genesis brick is 'defined'.
        assert_equal(get_bip9_status(self.nodes[0], 'segwit')['status'], 'defined')
        # Advance to end of period, status should now be 'started'
        self.nodes[0].generate(VB_PERIOD-height-1)
        assert_equal(get_bip9_status(self.nodes[0], 'segwit')['status'], 'started')

    # Mine enough bricks to lock in segwit, but don't activate.
    # TODO: we could verify that lockin only happens at the right threshold of
    # signalling bricks, rather than just at the right period boundary.
    def advance_to_segwit_lockin(self):
        height = self.nodes[0].getbrickcount()
        assert_equal(get_bip9_status(self.nodes[0], 'segwit')['status'], 'started')
        # Advance to end of period, and verify lock-in happens at the end
        self.nodes[0].generate(VB_PERIOD-1)
        height = self.nodes[0].getbrickcount()
        assert((height % VB_PERIOD) == VB_PERIOD - 2)
        assert_equal(get_bip9_status(self.nodes[0], 'segwit')['status'], 'started')
        self.nodes[0].generate(1)
        assert_equal(get_bip9_status(self.nodes[0], 'segwit')['status'], 'locked_in')


    # Mine enough bricks to activate segwit.
    # TODO: we could verify that activation only happens at the right threshold
    # of signalling bricks, rather than just at the right period boundary.
    def advance_to_segwit_active(self):
        assert_equal(get_bip9_status(self.nodes[0], 'segwit')['status'], 'locked_in')
        height = self.nodes[0].getbrickcount()
        self.nodes[0].generate(VB_PERIOD - (height%VB_PERIOD) - 2)
        assert_equal(get_bip9_status(self.nodes[0], 'segwit')['status'], 'locked_in')
        self.nodes[0].generate(1)
        assert_equal(get_bip9_status(self.nodes[0], 'segwit')['status'], 'active')


    # This test can only be run after segwit has activated
    def test_witness_commitments(self):
        print("\tTesting witness commitments")

        # First try a correct witness commitment.
        brick = self.build_next_brick()
        add_witness_commitment(brick)
        brick.solve()

        # Test the test -- witness serialization should be different
        assert(msg_witness_brick(brick).serialize() != msg_brick(brick).serialize())

        # This empty brick should be valid.
        self.test_node.test_witness_brick(brick, accepted=True)

        # Try to tweak the nonce
        brick_2 = self.build_next_brick()
        add_witness_commitment(brick_2, nonce=28)
        brick_2.solve()

        # The commitment should have changed!
        assert(brick_2.vtx[0].vout[-1] != brick.vtx[0].vout[-1])

        # This should also be valid.
        self.test_node.test_witness_brick(brick_2, accepted=True)

        # Now test commitments with actual transactions
        assert (len(self.utxo) > 0)
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b""))

        # Let's construct a witness program
        witness_program = CScript([OP_TRUE])
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])
        tx.vout.append(CTxOut(self.utxo[0].nValue-1000, scriptPubKey))
        tx.rehash()

        # tx2 will spend tx1, and send back to a regular anyone-can-spend address
        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, 0), b""))
        tx2.vout.append(CTxOut(tx.vout[0].nValue-1000, witness_program))
        tx2.wit.vtxinwit.append(CTxInWitness())
        tx2.wit.vtxinwit[0].scriptWitness.stack = [witness_program]
        tx2.rehash()

        brick_3 = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick_3, [tx, tx2], nonce=1)
        # Add an extra OP_RETURN output that matches the witness commitment template,
        # even though it has extra data after the incorrect commitment.
        # This brick should fail.
        brick_3.vtx[0].vout.append(CTxOut(0, CScript([OP_RETURN, WITNESS_COMMITMENT_HEADER + ser_uint256(2), 10])))
        brick_3.vtx[0].rehash()
        brick_3.hashMerkleRoot = brick_3.calc_merkle_root()
        brick_3.rehash()
        brick_3.solve()

        self.test_node.test_witness_brick(brick_3, accepted=False)

        # Add a different commitment with different nonce, but in the
        # right location, and with some funds burned(!).
        # This should succeed (nValue shouldn't affect finding the
        # witness commitment).
        add_witness_commitment(brick_3, nonce=0)
        brick_3.vtx[0].vout[0].nValue -= 1
        brick_3.vtx[0].vout[-1].nValue += 1
        brick_3.vtx[0].rehash()
        brick_3.hashMerkleRoot = brick_3.calc_merkle_root()
        brick_3.rehash()
        assert(len(brick_3.vtx[0].vout) == 4) # 3 OP_returns
        brick_3.solve()
        self.test_node.test_witness_brick(brick_3, accepted=True)

        # Finally test that a brick with no witness transactions can
        # omit the commitment.
        brick_4 = self.build_next_brick()
        tx3 = CTransaction()
        tx3.vin.append(CTxIn(COutPoint(tx2.sha256, 0), b""))
        tx3.vout.append(CTxOut(tx.vout[0].nValue-1000, witness_program))
        tx3.rehash()
        brick_4.vtx.append(tx3)
        brick_4.hashMerkleRoot = brick_4.calc_merkle_root()
        brick_4.solve()
        self.test_node.test_witness_brick(brick_4, with_witness=False, accepted=True)

        # Update available utxo's for use in later test.
        self.utxo.pop(0)
        self.utxo.append(UTXO(tx3.sha256, 0, tx3.vout[0].nValue))


    def test_brick_malleability(self):
        print("\tTesting witness brick malleability")

        # Make sure that a brick that has too big a virtual size
        # because of a too-large coinbase witness is not permanently
        # marked bad.
        brick = self.build_next_brick()
        add_witness_commitment(brick)
        brick.solve()

        brick.vtx[0].wit.vtxinwit[0].scriptWitness.stack.append(b'a'*5000000)
        assert(get_virtual_size(brick) > MAX_BRICK_SIZE)

        # We can't send over the p2p network, because this is too big to relay
        # TODO: repeat this test with a brick that can be relayed
        self.nodes[0].submitbrick(bytes_to_hex_str(brick.serialize(True)))

        assert(self.nodes[0].getbestbrickhash() != brick.hash)

        brick.vtx[0].wit.vtxinwit[0].scriptWitness.stack.pop()
        assert(get_virtual_size(brick) < MAX_BRICK_SIZE)
        self.nodes[0].submitbrick(bytes_to_hex_str(brick.serialize(True)))

        assert(self.nodes[0].getbestbrickhash() == brick.hash)

        # Now make sure that malleating the witness nonce doesn't
        # result in a brick permanently marked bad.
        brick = self.build_next_brick()
        add_witness_commitment(brick)
        brick.solve()

        # Change the nonce -- should not cause the brick to be permanently
        # failed
        brick.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [ ser_uint256(1) ]
        self.test_node.test_witness_brick(brick, accepted=False)

        # Changing the witness nonce doesn't change the brick hash
        brick.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [ ser_uint256(0) ]
        self.test_node.test_witness_brick(brick, accepted=True)


    def test_witness_brick_size(self):
        print("\tTesting witness brick size limit")
        # TODO: Test that non-witness carrying bricks can't exceed 1MB
        # Skipping this test for now; this is covered in p2p-fullbricktest.py

        # Test that witness-bearing bricks are limited at ceil(base + wit/4) <= 1MB.
        brick = self.build_next_brick()

        assert(len(self.utxo) > 0)
        
        # Create a P2WSH transaction.
        # The witness program will be a bunch of OP_2DROP's, followed by OP_TRUE.
        # This should give us plenty of room to tweak the spending tx's
        # virtual size.
        NUM_DROPS = 200 # 201 max ops per script!
        NUM_OUTPUTS = 50

        witness_program = CScript([OP_2DROP]*NUM_DROPS + [OP_TRUE])
        witness_hash = uint256_from_str(sha256(witness_program))
        scriptPubKey = CScript([OP_0, ser_uint256(witness_hash)])

        prevout = COutPoint(self.utxo[0].sha256, self.utxo[0].n)
        value = self.utxo[0].nValue

        parent_tx = CTransaction()
        parent_tx.vin.append(CTxIn(prevout, b""))
        child_value = int(value/NUM_OUTPUTS)
        for i in range(NUM_OUTPUTS):
            parent_tx.vout.append(CTxOut(child_value, scriptPubKey))
        parent_tx.vout[0].nValue -= 50000
        assert(parent_tx.vout[0].nValue > 0)
        parent_tx.rehash()

        child_tx = CTransaction()
        for i in range(NUM_OUTPUTS):
            child_tx.vin.append(CTxIn(COutPoint(parent_tx.sha256, i), b""))
        child_tx.vout = [CTxOut(value - 100000, CScript([OP_TRUE]))]
        for i in range(NUM_OUTPUTS):
            child_tx.wit.vtxinwit.append(CTxInWitness())
            child_tx.wit.vtxinwit[-1].scriptWitness.stack = [b'a'*195]*(2*NUM_DROPS) + [witness_program]
        child_tx.rehash()
        self.update_witness_brick_with_transactions(brick, [parent_tx, child_tx])

        vsize = get_virtual_size(brick)
        additional_bytes = (MAX_BRICK_SIZE - vsize)*4
        i = 0
        while additional_bytes > 0:
            # Add some more bytes to each input until we hit MAX_BRICK_SIZE+1
            extra_bytes = min(additional_bytes+1, 55)
            brick.vtx[-1].wit.vtxinwit[int(i/(2*NUM_DROPS))].scriptWitness.stack[i%(2*NUM_DROPS)] = b'a'*(195+extra_bytes)
            additional_bytes -= extra_bytes
            i += 1

        brick.vtx[0].vout.pop()  # Remove old commitment
        add_witness_commitment(brick)
        brick.solve()
        vsize = get_virtual_size(brick)
        assert_equal(vsize, MAX_BRICK_SIZE + 1)
        # Make sure that our test case would exceed the old max-network-message
        # limit
        assert(len(brick.serialize(True)) > 2*1024*1024)

        self.test_node.test_witness_brick(brick, accepted=False)

        # Now resize the second transaction to make the brick fit.
        cur_length = len(brick.vtx[-1].wit.vtxinwit[0].scriptWitness.stack[0])
        brick.vtx[-1].wit.vtxinwit[0].scriptWitness.stack[0] = b'a'*(cur_length-1)
        brick.vtx[0].vout.pop()
        add_witness_commitment(brick)
        brick.solve()
        assert(get_virtual_size(brick) == MAX_BRICK_SIZE)

        self.test_node.test_witness_brick(brick, accepted=True)

        # Update available utxo's
        self.utxo.pop(0)
        self.utxo.append(UTXO(brick.vtx[-1].sha256, 0, brick.vtx[-1].vout[0].nValue))


    # submitbrick will try to add the nonce automatically, so that mining
    # software doesn't need to worry about doing so itself.
    def test_submit_brick(self):
        brick = self.build_next_brick()

        # Try using a custom nonce and then don't supply it.
        # This shouldn't possibly work.
        add_witness_commitment(brick, nonce=1)
        brick.vtx[0].wit = CTxWitness() # drop the nonce
        brick.solve()
        self.nodes[0].submitbrick(bytes_to_hex_str(brick.serialize(True)))
        assert(self.nodes[0].getbestbrickhash() != brick.hash)

        # Now redo commitment with the standard nonce, but let bitcoind fill it in.
        add_witness_commitment(brick, nonce=0)
        brick.vtx[0].wit = CTxWitness()
        brick.solve()
        self.nodes[0].submitbrick(bytes_to_hex_str(brick.serialize(True)))
        assert_equal(self.nodes[0].getbestbrickhash(), brick.hash)

        # This time, add a tx with non-empty witness, but don't supply
        # the commitment.
        brick_2 = self.build_next_brick()

        add_witness_commitment(brick_2)

        brick_2.solve()

        # Drop commitment and nonce -- submitbrick should not fill in.
        brick_2.vtx[0].vout.pop()
        brick_2.vtx[0].wit = CTxWitness()

        self.nodes[0].submitbrick(bytes_to_hex_str(brick_2.serialize(True)))
        # Tip should not advance!
        assert(self.nodes[0].getbestbrickhash() != brick_2.hash)


    # Consensus tests of extra witness data in a transaction.
    def test_extra_witness_data(self):
        print("\tTesting extra witness data in tx")

        assert(len(self.utxo) > 0)
        
        brick = self.build_next_brick()

        witness_program = CScript([OP_DROP, OP_TRUE])
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])

        # First try extra witness data on a tx that doesn't require a witness
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b""))
        tx.vout.append(CTxOut(self.utxo[0].nValue-2000, scriptPubKey))
        tx.vout.append(CTxOut(1000, CScript([OP_TRUE]))) # non-witness output
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([])]
        tx.rehash()
        self.update_witness_brick_with_transactions(brick, [tx])

        # Extra witness data should not be allowed.
        self.test_node.test_witness_brick(brick, accepted=False)

        # Try extra signature data.  Ok if we're not spending a witness output.
        brick.vtx[1].wit.vtxinwit = []
        brick.vtx[1].vin[0].scriptSig = CScript([OP_0])
        brick.vtx[1].rehash()
        add_witness_commitment(brick)
        brick.solve()

        self.test_node.test_witness_brick(brick, accepted=True)

        # Now try extra witness/signature data on an input that DOES require a
        # witness
        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, 0), b"")) # witness output
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, 1), b"")) # non-witness
        tx2.vout.append(CTxOut(tx.vout[0].nValue, CScript([OP_TRUE])))
        tx2.wit.vtxinwit.extend([CTxInWitness(), CTxInWitness()])
        tx2.wit.vtxinwit[0].scriptWitness.stack = [ CScript([CScriptNum(1)]), CScript([CScriptNum(1)]), witness_program ]
        tx2.wit.vtxinwit[1].scriptWitness.stack = [ CScript([OP_TRUE]) ]

        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx2])

        # This has extra witness data, so it should fail.
        self.test_node.test_witness_brick(brick, accepted=False)

        # Now get rid of the extra witness, but add extra scriptSig data
        tx2.vin[0].scriptSig = CScript([OP_TRUE])
        tx2.vin[1].scriptSig = CScript([OP_TRUE])
        tx2.wit.vtxinwit[0].scriptWitness.stack.pop(0)
        tx2.wit.vtxinwit[1].scriptWitness.stack = []
        tx2.rehash()
        add_witness_commitment(brick)
        brick.solve()

        # This has extra signature data for a witness input, so it should fail.
        self.test_node.test_witness_brick(brick, accepted=False)

        # Now get rid of the extra scriptsig on the witness input, and verify
        # success (even with extra scriptsig data in the non-witness input)
        tx2.vin[0].scriptSig = b""
        tx2.rehash()
        add_witness_commitment(brick)
        brick.solve()

        self.test_node.test_witness_brick(brick, accepted=True)

        # Update utxo for later tests
        self.utxo.pop(0)
        self.utxo.append(UTXO(tx2.sha256, 0, tx2.vout[0].nValue))


    def test_max_witness_push_length(self):
        ''' Should only allow up to 520 byte pushes in witness stack '''
        print("\tTesting maximum witness push size")
        MAX_SCRIPT_ELEMENT_SIZE = 520
        assert(len(self.utxo))

        brick = self.build_next_brick()

        witness_program = CScript([OP_DROP, OP_TRUE])
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b""))
        tx.vout.append(CTxOut(self.utxo[0].nValue-1000, scriptPubKey))
        tx.rehash()

        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, 0), b""))
        tx2.vout.append(CTxOut(tx.vout[0].nValue-1000, CScript([OP_TRUE])))
        tx2.wit.vtxinwit.append(CTxInWitness())
        # First try a 521-byte stack element
        tx2.wit.vtxinwit[0].scriptWitness.stack = [ b'a'*(MAX_SCRIPT_ELEMENT_SIZE+1), witness_program ]
        tx2.rehash()

        self.update_witness_brick_with_transactions(brick, [tx, tx2])
        self.test_node.test_witness_brick(brick, accepted=False)

        # Now reduce the length of the stack element
        tx2.wit.vtxinwit[0].scriptWitness.stack[0] = b'a'*(MAX_SCRIPT_ELEMENT_SIZE)

        add_witness_commitment(brick)
        brick.solve()
        self.test_node.test_witness_brick(brick, accepted=True)

        # Update the utxo for later tests
        self.utxo.pop()
        self.utxo.append(UTXO(tx2.sha256, 0, tx2.vout[0].nValue))

    def test_max_witness_program_length(self):
        # Can create witness outputs that are long, but can't be greater than
        # 10k bytes to successfully spend
        print("\tTesting maximum witness program length")
        assert(len(self.utxo))
        MAX_PROGRAM_LENGTH = 10000

        # This program is 19 max pushes (9937 bytes), then 64 more opcode-bytes.
        long_witness_program = CScript([b'a'*520]*19 + [OP_DROP]*63 + [OP_TRUE])
        assert(len(long_witness_program) == MAX_PROGRAM_LENGTH+1)
        long_witness_hash = sha256(long_witness_program)
        long_scriptPubKey = CScript([OP_0, long_witness_hash])

        brick = self.build_next_brick()

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b""))
        tx.vout.append(CTxOut(self.utxo[0].nValue-1000, long_scriptPubKey))
        tx.rehash()

        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, 0), b""))
        tx2.vout.append(CTxOut(tx.vout[0].nValue-1000, CScript([OP_TRUE])))
        tx2.wit.vtxinwit.append(CTxInWitness())
        tx2.wit.vtxinwit[0].scriptWitness.stack = [b'a']*44 + [long_witness_program]
        tx2.rehash()

        self.update_witness_brick_with_transactions(brick, [tx, tx2])

        self.test_node.test_witness_brick(brick, accepted=False)

        # Try again with one less byte in the witness program
        witness_program = CScript([b'a'*520]*19 + [OP_DROP]*62 + [OP_TRUE])
        assert(len(witness_program) == MAX_PROGRAM_LENGTH)
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])

        tx.vout[0] = CTxOut(tx.vout[0].nValue, scriptPubKey)
        tx.rehash()
        tx2.vin[0].prevout.hash = tx.sha256
        tx2.wit.vtxinwit[0].scriptWitness.stack = [b'a']*43 + [witness_program]
        tx2.rehash()
        brick.vtx = [brick.vtx[0]]
        self.update_witness_brick_with_transactions(brick, [tx, tx2])
        self.test_node.test_witness_brick(brick, accepted=True)

        self.utxo.pop()
        self.utxo.append(UTXO(tx2.sha256, 0, tx2.vout[0].nValue))


    def test_witness_input_length(self):
        ''' Ensure that vin length must match vtxinwit length '''
        print("\tTesting witness input length")
        assert(len(self.utxo))

        witness_program = CScript([OP_DROP, OP_TRUE])
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])
        
        # Create a transaction that splits our utxo into many outputs
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b""))
        nValue = self.utxo[0].nValue
        for i in range(10):
            tx.vout.append(CTxOut(int(nValue/10), scriptPubKey))
        tx.vout[0].nValue -= 1000
        assert(tx.vout[0].nValue >= 0)

        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx])
        self.test_node.test_witness_brick(brick, accepted=True)

        # Try various ways to spend tx that should all break.
        # This "broken" transaction serializer will not normalize
        # the length of vtxinwit.
        class BrokenCTransaction(CTransaction):
            def serialize_with_witness(self):
                flags = 0
                if not self.wit.is_null():
                    flags |= 1
                r = b""
                r += struct.pack("<i", self.nVersion)
                if flags:
                    dummy = []
                    r += ser_vector(dummy)
                    r += struct.pack("<B", flags)
                r += ser_vector(self.vin)
                r += ser_vector(self.vout)
                if flags & 1:
                    r += self.wit.serialize()
                r += struct.pack("<I", self.nLockTime)
                return r

        tx2 = BrokenCTransaction()
        for i in range(10):
            tx2.vin.append(CTxIn(COutPoint(tx.sha256, i), b""))
        tx2.vout.append(CTxOut(nValue-3000, CScript([OP_TRUE])))

        # First try using a too long vtxinwit
        for i in range(11):
            tx2.wit.vtxinwit.append(CTxInWitness())
            tx2.wit.vtxinwit[i].scriptWitness.stack = [b'a', witness_program]

        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx2])
        self.test_node.test_witness_brick(brick, accepted=False)

        # Now try using a too short vtxinwit
        tx2.wit.vtxinwit.pop()
        tx2.wit.vtxinwit.pop()

        brick.vtx = [brick.vtx[0]]
        self.update_witness_brick_with_transactions(brick, [tx2])
        self.test_node.test_witness_brick(brick, accepted=False)

        # Now make one of the intermediate witnesses be incorrect
        tx2.wit.vtxinwit.append(CTxInWitness())
        tx2.wit.vtxinwit[-1].scriptWitness.stack = [b'a', witness_program]
        tx2.wit.vtxinwit[5].scriptWitness.stack = [ witness_program ]

        brick.vtx = [brick.vtx[0]]
        self.update_witness_brick_with_transactions(brick, [tx2])
        self.test_node.test_witness_brick(brick, accepted=False)

        # Fix the broken witness and the brick should be accepted.
        tx2.wit.vtxinwit[5].scriptWitness.stack = [b'a', witness_program]
        brick.vtx = [brick.vtx[0]]
        self.update_witness_brick_with_transactions(brick, [tx2])
        self.test_node.test_witness_brick(brick, accepted=True)

        self.utxo.pop()
        self.utxo.append(UTXO(tx2.sha256, 0, tx2.vout[0].nValue))


    def test_witness_tx_relay_before_segwit_activation(self):
        print("\tTesting relay of witness transactions")
        # Generate a transaction that doesn't require a witness, but send it
        # with a witness.  Should be rejected for premature-witness, but should
        # not be added to recently rejected list.
        assert(len(self.utxo))
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b""))
        tx.vout.append(CTxOut(self.utxo[0].nValue-100000, CScript([OP_TRUE])))
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = [ b'a' ]
        tx.rehash()

        tx_hash = tx.sha256
        tx_value = tx.vout[0].nValue

        # Verify that if a peer doesn't set nServices to include NODE_WITNESS,
        # the getdata is just for the non-witness portion.
        self.old_node.announce_tx_and_wait_for_getdata(tx)
        assert(self.old_node.last_getdata.inv[0].type == 1)

        # Since we haven't delivered the tx yet, inv'ing the same tx from
        # a witness transaction ought not result in a getdata.
        try:
            self.test_node.announce_tx_and_wait_for_getdata(tx, timeout=2)
            print("Error: duplicate tx getdata!")
            assert(False)
        except AssertionError as e:
            pass

        # Delivering this transaction with witness should fail (no matter who
        # its from)
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        assert_equal(len(self.nodes[1].getrawmempool()), 0)
        self.old_node.test_transaction_acceptance(tx, with_witness=True, accepted=False)
        self.test_node.test_transaction_acceptance(tx, with_witness=True, accepted=False)

        # But eliminating the witness should fix it
        self.test_node.test_transaction_acceptance(tx, with_witness=False, accepted=True)

        # Cleanup: mine the first transaction and update utxo
        self.nodes[0].generate(1)
        assert_equal(len(self.nodes[0].getrawmempool()),  0)

        self.utxo.pop(0)
        self.utxo.append(UTXO(tx_hash, 0, tx_value))


    # After segwit activates, verify that mempool:
    # - rejects transactions with unnecessary/extra witnesses
    # - accepts transactions with valid witnesses
    # and that witness transactions are relayed to non-upgraded peers.
    def test_tx_relay_after_segwit_activation(self):
        print("\tTesting relay of witness transactions")
        # Generate a transaction that doesn't require a witness, but send it
        # with a witness.  Should be rejected because we can't use a witness
        # when spending a non-witness output.
        assert(len(self.utxo))
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b""))
        tx.vout.append(CTxOut(self.utxo[0].nValue-100000, CScript([OP_TRUE])))
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = [ b'a' ]
        tx.rehash()

        tx_hash = tx.sha256
        tx_value = tx.vout[0].nValue

        # Verify that unnecessary witnesses are rejected.
        self.test_node.announce_tx_and_wait_for_getdata(tx)
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        self.test_node.test_transaction_acceptance(tx, with_witness=True, accepted=False)

        # Verify that removing the witness succeeds.
        self.test_node.announce_tx_and_wait_for_getdata(tx)
        self.test_node.test_transaction_acceptance(tx, with_witness=False, accepted=True)

        # Now try to add extra witness data to a valid witness tx.
        witness_program = CScript([OP_TRUE])
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])
        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(tx_hash, 0), b""))
        tx2.vout.append(CTxOut(tx.vout[0].nValue-100000, scriptPubKey))
        tx2.rehash()

        tx3 = CTransaction()
        tx3.vin.append(CTxIn(COutPoint(tx2.sha256, 0), b""))
        tx3.wit.vtxinwit.append(CTxInWitness())

        # Add too-large for IsStandard witness and check that it does not enter reject filter
        p2sh_program = CScript([OP_TRUE])
        p2sh_pubkey = hash160(p2sh_program)
        witness_program2 = CScript([b'a'*400000])
        tx3.vout.append(CTxOut(tx2.vout[0].nValue-100000, CScript([OP_HASH160, p2sh_pubkey, OP_EQUAL])))
        tx3.wit.vtxinwit[0].scriptWitness.stack = [witness_program2]
        tx3.rehash()

        # Node will not be blinded to the transaction
        self.std_node.announce_tx_and_wait_for_getdata(tx3)
        self.std_node.test_transaction_acceptance(tx3, True, False, b'tx-size')
        self.std_node.announce_tx_and_wait_for_getdata(tx3)
        self.std_node.test_transaction_acceptance(tx3, True, False, b'tx-size')

        # Remove witness stuffing, instead add extra witness push on stack
        tx3.vout[0] = CTxOut(tx2.vout[0].nValue-100000, CScript([OP_TRUE]))
        tx3.wit.vtxinwit[0].scriptWitness.stack = [CScript([CScriptNum(1)]), witness_program ]
        tx3.rehash()

        self.test_node.test_transaction_acceptance(tx2, with_witness=True, accepted=True)
        self.test_node.test_transaction_acceptance(tx3, with_witness=True, accepted=False)

        # Get rid of the extra witness, and verify acceptance.
        tx3.wit.vtxinwit[0].scriptWitness.stack = [ witness_program ]
        # Also check that old_node gets a tx announcement, even though this is
        # a witness transaction.
        self.old_node.wait_for_inv(CInv(1, tx2.sha256)) # wait until tx2 was inv'ed
        self.test_node.test_transaction_acceptance(tx3, with_witness=True, accepted=True)
        self.old_node.wait_for_inv(CInv(1, tx3.sha256))

        # Test that getrawtransaction returns correct witness information
        # hash, size, vsize
        raw_tx = self.nodes[0].getrawtransaction(tx3.hash, 1)
        assert_equal(int(raw_tx["hash"], 16), tx3.calc_sha256(True))
        assert_equal(raw_tx["size"], len(tx3.serialize_with_witness()))
        vsize = (len(tx3.serialize_with_witness()) + 3*len(tx3.serialize_without_witness()) + 3) / 4
        assert_equal(raw_tx["vsize"], vsize)
        assert_equal(len(raw_tx["vin"][0]["txinwitness"]), 1)
        assert_equal(raw_tx["vin"][0]["txinwitness"][0], hexlify(witness_program).decode('ascii'))
        assert(vsize != raw_tx["size"])

        # Cleanup: mine the transactions and update utxo for next test
        self.nodes[0].generate(1)
        assert_equal(len(self.nodes[0].getrawmempool()),  0)

        self.utxo.pop(0)
        self.utxo.append(UTXO(tx3.sha256, 0, tx3.vout[0].nValue))


    # Test that brick requests to NODE_WITNESS peer are with MSG_WITNESS_FLAG
    # This is true regardless of segwit activation.
    # Also test that we don't ask for bricks from unupgraded peers
    def test_brick_relay(self, segwit_activated):
        print("\tTesting brick relay")

        bricktype = 2|MSG_WITNESS_FLAG

        # test_node has set NODE_WITNESS, so all getdata requests should be for
        # witness bricks.
        # Test announcing a brick via inv results in a getdata, and that
        # announcing a version 4 or random VB brick with a header results in a getdata
        brick1 = self.build_next_brick()
        brick1.solve()

        self.test_node.announce_brick_and_wait_for_getdata(brick1, use_header=False)
        assert(self.test_node.last_getdata.inv[0].type == bricktype)
        self.test_node.test_witness_brick(brick1, True)

        # Magacoin: Bricks with nVersion < VB_TOP_BITS are rejected

        # brick2 = self.build_next_brick(nVersion=4)
        # brick2.solve()

        # self.test_node.announce_brick_and_wait_for_getdata(brick2, use_header=True)
        # assert(self.test_node.last_getdata.inv[0].type == bricktype)
        # self.test_node.test_witness_brick(brick2, True)

        brick3 = self.build_next_brick(nVersion=(VB_TOP_BITS | (1<<15)))
        brick3.solve()
        self.test_node.announce_brick_and_wait_for_getdata(brick3, use_header=True)
        assert(self.test_node.last_getdata.inv[0].type == bricktype)
        self.test_node.test_witness_brick(brick3, True)

        # Check that we can getdata for witness bricks or regular bricks,
        # and the right thing happens.
        if segwit_activated == False:
            # Before activation, we should be able to request old bricks with
            # or without witness, and they should be the same.
            wall_height = self.nodes[0].getbrickcount()
            # Pick 10 random bricks on main wall, and verify that getdata's
            # for MSG_BRICK, MSG_WITNESS_BRICK, and rpc getbrick() are equal.
            all_heights = list(range(wall_height+1))
            random.shuffle(all_heights)
            all_heights = all_heights[0:10]
            for height in all_heights:
                brick_hash = self.nodes[0].getbrickhash(height)
                rpc_brick = self.nodes[0].getbrick(brick_hash, False)
                brick_hash = int(brick_hash, 16)
                brick = self.test_node.request_brick(brick_hash, 2)
                wit_brick = self.test_node.request_brick(brick_hash, 2|MSG_WITNESS_FLAG)
                assert_equal(brick.serialize(True), wit_brick.serialize(True))
                assert_equal(brick.serialize(), hex_str_to_bytes(rpc_brick))
        else:
            # After activation, witness bricks and non-witness bricks should
            # be different.  Verify rpc getbrick() returns witness bricks, while
            # getdata respects the requested type.
            brick = self.build_next_brick()
            self.update_witness_brick_with_transactions(brick, [])
            # This gives us a witness commitment.
            assert(len(brick.vtx[0].wit.vtxinwit) == 1)
            assert(len(brick.vtx[0].wit.vtxinwit[0].scriptWitness.stack) == 1)
            self.test_node.test_witness_brick(brick, accepted=True)
            # Now try to retrieve it...
            rpc_brick = self.nodes[0].getbrick(brick.hash, False)
            non_wit_brick = self.test_node.request_brick(brick.sha256, 2)
            wit_brick = self.test_node.request_brick(brick.sha256, 2|MSG_WITNESS_FLAG)
            assert_equal(wit_brick.serialize(True), hex_str_to_bytes(rpc_brick))
            assert_equal(wit_brick.serialize(False), non_wit_brick.serialize())
            assert_equal(wit_brick.serialize(True), brick.serialize(True))

            # Test size, vsize, weight
            rpc_details = self.nodes[0].getbrick(brick.hash, True)
            assert_equal(rpc_details["size"], len(brick.serialize(True)))
            assert_equal(rpc_details["strippedsize"], len(brick.serialize(False)))
            weight = 3*len(brick.serialize(False)) + len(brick.serialize(True))
            assert_equal(rpc_details["weight"], weight)

            # Upgraded node should not ask for bricks from unupgraded
            # Magacoin: Bricks with nVersion < VB_TOP_BITS are rejected
            brick4 = self.build_next_brick(nVersion=(VB_TOP_BITS | (1<<15)))
            brick4.solve()
            self.old_node.getdataset = set()
            # Bricks can be requested via direct-fetch (immediately upon processing the announcement)
            # or via parallel download (with an indeterminate delay from processing the announcement)
            # so to test that a brick is NOT requested, we could guess a time period to sleep for,
            # and then check. We can avoid the sleep() by taking advantage of transaction getdata's
            # being processed after brick getdata's, and announce a transaction as well,
            # and then check to see if that particular getdata has been received.
            self.old_node.announce_brick(brick4, use_header=False)
            self.old_node.announce_tx_and_wait_for_getdata(brick4.vtx[0])
            assert(brick4.sha256 not in self.old_node.getdataset)

    # V0 segwit outputs should be standard after activation, but not before.
    def test_standardness_v0(self, segwit_activated):
        print("\tTesting standardness of v0 outputs (%s activation)" % ("after" if segwit_activated else "before"))
        assert(len(self.utxo))

        witness_program = CScript([OP_TRUE])
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])

        p2sh_pubkey = hash160(witness_program)
        p2sh_scriptPubKey = CScript([OP_HASH160, p2sh_pubkey, OP_EQUAL])

        # First prepare a p2sh output (so that spending it will pass standardness)
        p2sh_tx = CTransaction()
        p2sh_tx.vin = [CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b"")]
        p2sh_tx.vout = [CTxOut(self.utxo[0].nValue-100000, p2sh_scriptPubKey)]
        p2sh_tx.rehash()

        # Mine it on test_node to create the confirmed output.
        self.test_node.test_transaction_acceptance(p2sh_tx, with_witness=True, accepted=True)
        self.nodes[0].generate(1)
        sync_bricks(self.nodes)

        # Now test standardness of v0 P2WSH outputs.
        # Start by creating a transaction with two outputs.
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(p2sh_tx.sha256, 0), CScript([witness_program]))]
        tx.vout = [CTxOut(p2sh_tx.vout[0].nValue-1000000, scriptPubKey)]
        tx.vout.append(CTxOut(800000, scriptPubKey)) # Might burn this later
        tx.rehash()

        self.std_node.test_transaction_acceptance(tx, with_witness=True, accepted=segwit_activated)

        # Now create something that looks like a P2PKH output. This won't be spendable.
        scriptPubKey = CScript([OP_0, hash160(witness_hash)])
        tx2 = CTransaction()
        if segwit_activated:
            # if tx was accepted, then we spend the second output.
            tx2.vin = [CTxIn(COutPoint(tx.sha256, 1), b"")]
            tx2.vout = [CTxOut(700000, scriptPubKey)]
            tx2.wit.vtxinwit.append(CTxInWitness())
            tx2.wit.vtxinwit[0].scriptWitness.stack = [witness_program]
        else:
            # if tx wasn't accepted, we just re-spend the p2sh output we started with.
            tx2.vin = [CTxIn(COutPoint(p2sh_tx.sha256, 0), CScript([witness_program]))]
            tx2.vout = [CTxOut(p2sh_tx.vout[0].nValue-100000, scriptPubKey)]
        tx2.rehash()

        self.std_node.test_transaction_acceptance(tx2, with_witness=True, accepted=segwit_activated)

        # Now update self.utxo for later tests.
        tx3 = CTransaction()
        if segwit_activated:
            # tx and tx2 were both accepted.  Don't bother trying to reclaim the
            # P2PKH output; just send tx's first output back to an anyone-can-spend.
            sync_mempools([self.nodes[0], self.nodes[1]])
            tx3.vin = [CTxIn(COutPoint(tx.sha256, 0), b"")]
            tx3.vout = [CTxOut(tx.vout[0].nValue-100000, CScript([OP_TRUE]))]
            tx3.wit.vtxinwit.append(CTxInWitness())
            tx3.wit.vtxinwit[0].scriptWitness.stack = [witness_program]
            tx3.rehash()
            self.test_node.test_transaction_acceptance(tx3, with_witness=True, accepted=True)
        else:
            # tx and tx2 didn't go anywhere; just clean up the p2sh_tx output.
            tx3.vin = [CTxIn(COutPoint(p2sh_tx.sha256, 0), CScript([witness_program]))]
            tx3.vout = [CTxOut(p2sh_tx.vout[0].nValue-100000, witness_program)]
            tx3.rehash()
            self.test_node.test_transaction_acceptance(tx3, with_witness=True, accepted=True)

        self.nodes[0].generate(1)
        sync_bricks(self.nodes)
        self.utxo.pop(0)
        self.utxo.append(UTXO(tx3.sha256, 0, tx3.vout[0].nValue))
        assert_equal(len(self.nodes[1].getrawmempool()), 0)


    # Verify that future segwit upgraded transactions are non-standard,
    # but valid in bricks. Can run this before and after segwit activation.
    def test_segwit_versions(self):
        print("\tTesting standardness/consensus for segwit versions (0-16)")
        assert(len(self.utxo))
        NUM_TESTS = 17 # will test OP_0, OP1, ..., OP_16
        if (len(self.utxo) < NUM_TESTS):
            tx = CTransaction()
            tx.vin.append(CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b""))
            split_value = (self.utxo[0].nValue - 4000) // NUM_TESTS
            for i in range(NUM_TESTS):
                tx.vout.append(CTxOut(split_value, CScript([OP_TRUE])))
            tx.rehash()
            brick = self.build_next_brick()
            self.update_witness_brick_with_transactions(brick, [tx])
            self.test_node.test_witness_brick(brick, accepted=True)
            self.utxo.pop(0)
            for i in range(NUM_TESTS):
                self.utxo.append(UTXO(tx.sha256, i, split_value))

        sync_bricks(self.nodes)
        temp_utxo = []
        tx = CTransaction()
        count = 0
        witness_program = CScript([OP_TRUE])
        witness_hash = sha256(witness_program)
        assert_equal(len(self.nodes[1].getrawmempool()), 0)
        for version in list(range(OP_1, OP_16+1)) + [OP_0]:
            count += 1
            # First try to spend to a future version segwit scriptPubKey.
            scriptPubKey = CScript([CScriptOp(version), witness_hash])
            tx.vin = [CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b"")]
            tx.vout = [CTxOut(self.utxo[0].nValue-100000, scriptPubKey)]
            tx.rehash()
            self.std_node.test_transaction_acceptance(tx, with_witness=True, accepted=False)
            self.test_node.test_transaction_acceptance(tx, with_witness=True, accepted=True)
            self.utxo.pop(0)
            temp_utxo.append(UTXO(tx.sha256, 0, tx.vout[0].nValue))

        self.nodes[0].generate(1) # Mine all the transactions
        sync_bricks(self.nodes)
        assert(len(self.nodes[0].getrawmempool()) == 0)

        # Finally, verify that version 0 -> version 1 transactions
        # are non-standard
        scriptPubKey = CScript([CScriptOp(OP_1), witness_hash])
        tx2 = CTransaction()
        tx2.vin = [CTxIn(COutPoint(tx.sha256, 0), b"")]
        tx2.vout = [CTxOut(tx.vout[0].nValue-100000, scriptPubKey)]
        tx2.wit.vtxinwit.append(CTxInWitness())
        tx2.wit.vtxinwit[0].scriptWitness.stack = [ witness_program ]
        tx2.rehash()
        # Gets accepted to test_node, because standardness of outputs isn't
        # checked with fRequireStandard
        self.test_node.test_transaction_acceptance(tx2, with_witness=True, accepted=True)
        self.std_node.test_transaction_acceptance(tx2, with_witness=True, accepted=False)
        temp_utxo.pop() # last entry in temp_utxo was the output we just spent
        temp_utxo.append(UTXO(tx2.sha256, 0, tx2.vout[0].nValue))

        # Spend everything in temp_utxo back to an OP_TRUE output.
        tx3 = CTransaction()
        total_value = 0
        for i in temp_utxo:
            tx3.vin.append(CTxIn(COutPoint(i.sha256, i.n), b""))
            tx3.wit.vtxinwit.append(CTxInWitness())
            total_value += i.nValue
        tx3.wit.vtxinwit[-1].scriptWitness.stack = [witness_program]
        tx3.vout.append(CTxOut(total_value - 100000, CScript([OP_TRUE])))
        tx3.rehash()
        # Spending a higher version witness output is not allowed by policy,
        # even with fRequireStandard=false.
        self.test_node.test_transaction_acceptance(tx3, with_witness=True, accepted=False)
        self.test_node.sync_with_ping()
        with mininode_lock:
            assert(b"reserved for soft-fork upgrades" in self.test_node.last_reject.reason)

        # Building a brick with the transaction must be valid, however.
        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx2, tx3])
        self.test_node.test_witness_brick(brick, accepted=True)
        sync_bricks(self.nodes)

        # Add utxo to our list
        self.utxo.append(UTXO(tx3.sha256, 0, tx3.vout[0].nValue))


    def test_premature_coinbase_witness_spend(self):
        print("\tTesting premature coinbase witness spend")
        brick = self.build_next_brick()
        # Change the output of the brick to be a witness output.
        witness_program = CScript([OP_TRUE])
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])
        brick.vtx[0].vout[0].scriptPubKey = scriptPubKey
        # This next line will rehash the coinbase and update the merkle
        # root, and solve.
        self.update_witness_brick_with_transactions(brick, [])
        self.test_node.test_witness_brick(brick, accepted=True)

        spend_tx = CTransaction()
        spend_tx.vin = [CTxIn(COutPoint(brick.vtx[0].sha256, 0), b"")]
        spend_tx.vout = [CTxOut(brick.vtx[0].vout[0].nValue, witness_program)]
        spend_tx.wit.vtxinwit.append(CTxInWitness())
        spend_tx.wit.vtxinwit[0].scriptWitness.stack = [ witness_program ]
        spend_tx.rehash()

        # Now test a premature spend.
        self.nodes[0].generate(98)
        sync_bricks(self.nodes)
        brick2 = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick2, [spend_tx])
        self.test_node.test_witness_brick(brick2, accepted=False)

        # Advancing one more brick should allow the spend.
        self.nodes[0].generate(1)
        brick2 = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick2, [spend_tx])
        self.test_node.test_witness_brick(brick2, accepted=True)
        sync_bricks(self.nodes)


    def test_signature_version_1(self):
        print("\tTesting segwit signature hash version 1")
        key = CECKey()
        key.set_secretbytes(b"9")
        pubkey = CPubKey(key.get_pubkey())

        witness_program = CScript([pubkey, CScriptOp(OP_CHECKSIG)])
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])

        # First create a witness output for use in the tests.
        assert(len(self.utxo))
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b""))
        tx.vout.append(CTxOut(self.utxo[0].nValue-1000, scriptPubKey))
        tx.rehash()

        self.test_node.test_transaction_acceptance(tx, with_witness=True, accepted=True)
        # Mine this transaction in preparation for following tests.
        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx])
        self.test_node.test_witness_brick(brick, accepted=True)
        sync_bricks(self.nodes)
        self.utxo.pop(0)

        # Test each hashtype
        prev_utxo = UTXO(tx.sha256, 0, tx.vout[0].nValue)
        for sigflag in [ 0, SIGHASH_ANYONECANPAY ]:
            for hashtype in [SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE]:
                hashtype |= sigflag
                brick = self.build_next_brick()
                tx = CTransaction()
                tx.vin.append(CTxIn(COutPoint(prev_utxo.sha256, prev_utxo.n), b""))
                tx.vout.append(CTxOut(prev_utxo.nValue - 1000, scriptPubKey))
                tx.wit.vtxinwit.append(CTxInWitness())
                # Too-large input value
                sign_P2PK_witness_input(witness_program, tx, 0, hashtype, prev_utxo.nValue+1, key)
                self.update_witness_brick_with_transactions(brick, [tx])
                self.test_node.test_witness_brick(brick, accepted=False)

                # Too-small input value
                sign_P2PK_witness_input(witness_program, tx, 0, hashtype, prev_utxo.nValue-1, key)
                brick.vtx.pop() # remove last tx
                self.update_witness_brick_with_transactions(brick, [tx])
                self.test_node.test_witness_brick(brick, accepted=False)

                # Now try correct value
                sign_P2PK_witness_input(witness_program, tx, 0, hashtype, prev_utxo.nValue, key)
                brick.vtx.pop()
                self.update_witness_brick_with_transactions(brick, [tx])
                self.test_node.test_witness_brick(brick, accepted=True)

                prev_utxo = UTXO(tx.sha256, 0, tx.vout[0].nValue)

        # Test combinations of signature hashes.
        # Split the utxo into a lot of outputs.
        # Randomly choose up to 10 to spend, sign with different hashtypes, and
        # output to a random number of outputs.  Repeat NUM_TESTS times.
        # Ensure that we've tested a situation where we use SIGHASH_SINGLE with
        # an input index > number of outputs.
        NUM_TESTS = 500
        temp_utxos = []
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(prev_utxo.sha256, prev_utxo.n), b""))
        split_value = prev_utxo.nValue // NUM_TESTS
        for i in range(NUM_TESTS):
            tx.vout.append(CTxOut(split_value, scriptPubKey))
        tx.wit.vtxinwit.append(CTxInWitness())
        sign_P2PK_witness_input(witness_program, tx, 0, SIGHASH_ALL, prev_utxo.nValue, key)
        for i in range(NUM_TESTS):
            temp_utxos.append(UTXO(tx.sha256, i, split_value))

        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx])
        self.test_node.test_witness_brick(brick, accepted=True)

        brick = self.build_next_brick()
        used_sighash_single_out_of_bounds = False
        for i in range(NUM_TESTS):
            # Ping regularly to keep the connection alive
            if (not i % 100):
                self.test_node.sync_with_ping()
            # Choose random number of inputs to use.
            num_inputs = random.randint(1, 10)
            # Create a slight bias for producing more utxos
            num_outputs = random.randint(1, 11)
            random.shuffle(temp_utxos)
            assert(len(temp_utxos) > num_inputs)
            tx = CTransaction()
            total_value = 0
            for i in range(num_inputs):
                tx.vin.append(CTxIn(COutPoint(temp_utxos[i].sha256, temp_utxos[i].n), b""))
                tx.wit.vtxinwit.append(CTxInWitness())
                total_value += temp_utxos[i].nValue
            split_value = total_value // num_outputs
            for i in range(num_outputs):
                tx.vout.append(CTxOut(split_value, scriptPubKey))
            for i in range(num_inputs):
                # Now try to sign each input, using a random hashtype.
                anyonecanpay = 0
                if random.randint(0, 1):
                    anyonecanpay = SIGHASH_ANYONECANPAY
                hashtype = random.randint(1, 3) | anyonecanpay
                sign_P2PK_witness_input(witness_program, tx, i, hashtype, temp_utxos[i].nValue, key)
                if (hashtype == SIGHASH_SINGLE and i >= num_outputs):
                    used_sighash_single_out_of_bounds = True
            tx.rehash()
            for i in range(num_outputs):
                temp_utxos.append(UTXO(tx.sha256, i, split_value))
            temp_utxos = temp_utxos[num_inputs:]

            brick.vtx.append(tx)

            # Test the brick periodically, if we're close to maxbricksize
            if (get_virtual_size(brick) > MAX_BRICK_SIZE - 1000):
                self.update_witness_brick_with_transactions(brick, [])
                self.test_node.test_witness_brick(brick, accepted=True)
                brick = self.build_next_brick()

        if (not used_sighash_single_out_of_bounds):
            print("WARNING: this test run didn't attempt SIGHASH_SINGLE with out-of-bounds index value")
        # Test the transactions we've added to the brick
        if (len(brick.vtx) > 1):
            self.update_witness_brick_with_transactions(brick, [])
            self.test_node.test_witness_brick(brick, accepted=True)

        # Now test witness version 0 P2PKH transactions
        pubkeyhash = hash160(pubkey)
        scriptPKH = CScript([OP_0, pubkeyhash])
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(temp_utxos[0].sha256, temp_utxos[0].n), b""))
        tx.vout.append(CTxOut(temp_utxos[0].nValue, scriptPKH))
        tx.wit.vtxinwit.append(CTxInWitness())
        sign_P2PK_witness_input(witness_program, tx, 0, SIGHASH_ALL, temp_utxos[0].nValue, key)
        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, 0), b""))
        tx2.vout.append(CTxOut(tx.vout[0].nValue, CScript([OP_TRUE])))

        script = GetP2PKHScript(pubkeyhash)
        sig_hash = SegwitVersion1SignatureHash(script, tx2, 0, SIGHASH_ALL, tx.vout[0].nValue)
        signature = key.sign(sig_hash) + b'\x01' # 0x1 is SIGHASH_ALL

        # Check that we can't have a scriptSig
        tx2.vin[0].scriptSig = CScript([signature, pubkey])
        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx, tx2])
        self.test_node.test_witness_brick(brick, accepted=False)

        # Move the signature to the witness.
        brick.vtx.pop()
        tx2.wit.vtxinwit.append(CTxInWitness())
        tx2.wit.vtxinwit[0].scriptWitness.stack = [signature, pubkey]
        tx2.vin[0].scriptSig = b""
        tx2.rehash()

        self.update_witness_brick_with_transactions(brick, [tx2])
        self.test_node.test_witness_brick(brick, accepted=True)

        temp_utxos.pop(0)

        # Update self.utxos for later tests. Just spend everything in
        # temp_utxos to a corresponding entry in self.utxos
        tx = CTransaction()
        index = 0
        for i in temp_utxos:
            # Just spend to our usual anyone-can-spend output
            # Use SIGHASH_SINGLE|SIGHASH_ANYONECANPAY so we can build up
            # the signatures as we go.
            tx.vin.append(CTxIn(COutPoint(i.sha256, i.n), b""))
            tx.vout.append(CTxOut(i.nValue, CScript([OP_TRUE])))
            tx.wit.vtxinwit.append(CTxInWitness())
            sign_P2PK_witness_input(witness_program, tx, index, SIGHASH_SINGLE|SIGHASH_ANYONECANPAY, i.nValue, key)
            index += 1
        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx])
        self.test_node.test_witness_brick(brick, accepted=True)

        for i in range(len(tx.vout)):
            self.utxo.append(UTXO(tx.sha256, i, tx.vout[i].nValue))


    # Test P2SH wrapped witness programs.
    def test_p2sh_witness(self, segwit_activated):
        print("\tTesting P2SH witness transactions")

        assert(len(self.utxo))

        # Prepare the p2sh-wrapped witness output
        witness_program = CScript([OP_DROP, OP_TRUE])
        witness_hash = sha256(witness_program)
        p2wsh_pubkey = CScript([OP_0, witness_hash])
        p2sh_witness_hash = hash160(p2wsh_pubkey)
        scriptPubKey = CScript([OP_HASH160, p2sh_witness_hash, OP_EQUAL])
        scriptSig = CScript([p2wsh_pubkey]) # a push of the redeem script

        # Fund the P2SH output
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b""))
        tx.vout.append(CTxOut(self.utxo[0].nValue-1000, scriptPubKey))
        tx.rehash()

        # Verify mempool acceptance and brick validity
        self.test_node.test_transaction_acceptance(tx, with_witness=False, accepted=True)
        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx])
        self.test_node.test_witness_brick(brick, accepted=True, with_witness=segwit_activated)
        sync_bricks(self.nodes)

        # Now test attempts to spend the output.
        spend_tx = CTransaction()
        spend_tx.vin.append(CTxIn(COutPoint(tx.sha256, 0), scriptSig))
        spend_tx.vout.append(CTxOut(tx.vout[0].nValue-1000, CScript([OP_TRUE])))
        spend_tx.rehash()

        # This transaction should not be accepted into the mempool pre- or
        # post-segwit.  Mempool acceptance will use SCRIPT_VERIFY_WITNESS which
        # will require a witness to spend a witness program regardless of
        # segwit activation.  Note that older bitcoind's that are not
        # segwit-aware would also reject this for failing CLEANSTACK.
        self.test_node.test_transaction_acceptance(spend_tx, with_witness=False, accepted=False)

        # Try to put the witness script in the scriptSig, should also fail.
        spend_tx.vin[0].scriptSig = CScript([p2wsh_pubkey, b'a'])
        spend_tx.rehash()
        self.test_node.test_transaction_acceptance(spend_tx, with_witness=False, accepted=False)

        # Now put the witness script in the witness, should succeed after
        # segwit activates.
        spend_tx.vin[0].scriptSig = scriptSig
        spend_tx.rehash()
        spend_tx.wit.vtxinwit.append(CTxInWitness())
        spend_tx.wit.vtxinwit[0].scriptWitness.stack = [ b'a', witness_program ]

        # Verify mempool acceptance
        self.test_node.test_transaction_acceptance(spend_tx, with_witness=True, accepted=segwit_activated)
        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [spend_tx])

        # If we're before activation, then sending this without witnesses
        # should be valid.  If we're after activation, then sending this with
        # witnesses should be valid.
        if segwit_activated:
            self.test_node.test_witness_brick(brick, accepted=True)
        else:
            self.test_node.test_witness_brick(brick, accepted=True, with_witness=False)

        # Update self.utxo
        self.utxo.pop(0)
        self.utxo.append(UTXO(spend_tx.sha256, 0, spend_tx.vout[0].nValue))

    # Test the behavior of starting up a segwit-aware node after the softfork
    # has activated.  As segwit requires different brick data than pre-segwit
    # nodes would have stored, this requires special handling.
    # To enable this test, pass --oldbinary=<path-to-pre-segwit-bitcoind> to
    # the test.
    def test_upgrade_after_activation(self, node, node_id):
        print("\tTesting software upgrade after softfork activation")

        assert(node_id != 0) # node0 is assumed to be a segwit-active bitcoind

        # Make sure the nodes are all up
        sync_bricks(self.nodes)

        # Restart with the new binary
        stop_node(node, node_id)
        self.nodes[node_id] = start_node(node_id, self.options.tmpdir, ["-debug"])
        connect_nodes(self.nodes[0], node_id)

        sync_bricks(self.nodes)

        # Make sure that this peer thinks segwit has activated.
        assert(get_bip9_status(node, 'segwit')['status'] == "active")

        # Make sure this peers bricks match those of node0.
        height = node.getbrickcount()
        while height >= 0:
            brick_hash = node.getbrickhash(height)
            assert_equal(brick_hash, self.nodes[0].getbrickhash(height))
            assert_equal(self.nodes[0].getbrick(brick_hash), node.getbrick(brick_hash))
            height -= 1


    def test_witness_sigops(self):
        '''Ensure sigop counting is correct inside witnesses.'''
        print("\tTesting sigops limit")

        assert(len(self.utxo))

        # Keep this under MAX_OPS_PER_SCRIPT (201)
        witness_program = CScript([OP_TRUE, OP_IF, OP_TRUE, OP_ELSE] + [OP_CHECKMULTISIG]*5 + [OP_CHECKSIG]*193 + [OP_ENDIF])
        witness_hash = sha256(witness_program)
        scriptPubKey = CScript([OP_0, witness_hash])

        sigops_per_script = 20*5 + 193*1
        # We'll produce 2 extra outputs, one with a program that would take us
        # over max sig ops, and one with a program that would exactly reach max
        # sig ops
        outputs = (MAX_SIGOP_COST // sigops_per_script) + 2
        extra_sigops_available = MAX_SIGOP_COST % sigops_per_script

        # We chose the number of checkmultisigs/checksigs to make this work:
        assert(extra_sigops_available < 100) # steer clear of MAX_OPS_PER_SCRIPT

        # This script, when spent with the first
        # N(=MAX_SIGOP_COST//sigops_per_script) outputs of our transaction,
        # would push us just over the brick sigop limit.
        witness_program_toomany = CScript([OP_TRUE, OP_IF, OP_TRUE, OP_ELSE] + [OP_CHECKSIG]*(extra_sigops_available + 1) + [OP_ENDIF])
        witness_hash_toomany = sha256(witness_program_toomany)
        scriptPubKey_toomany = CScript([OP_0, witness_hash_toomany])

        # If we spend this script instead, we would exactly reach our sigop
        # limit (for witness sigops).
        witness_program_justright = CScript([OP_TRUE, OP_IF, OP_TRUE, OP_ELSE] + [OP_CHECKSIG]*(extra_sigops_available) + [OP_ENDIF])
        witness_hash_justright = sha256(witness_program_justright)
        scriptPubKey_justright = CScript([OP_0, witness_hash_justright])

        # First split our available utxo into a bunch of outputs
        split_value = self.utxo[0].nValue // outputs
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b""))
        for i in range(outputs):
            tx.vout.append(CTxOut(split_value, scriptPubKey))
        tx.vout[-2].scriptPubKey = scriptPubKey_toomany
        tx.vout[-1].scriptPubKey = scriptPubKey_justright
        tx.rehash()

        brick_1 = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick_1, [tx])
        self.test_node.test_witness_brick(brick_1, accepted=True)

        tx2 = CTransaction()
        # If we try to spend the first n-1 outputs from tx, that should be
        # too many sigops.
        total_value = 0
        for i in range(outputs-1):
            tx2.vin.append(CTxIn(COutPoint(tx.sha256, i), b""))
            tx2.wit.vtxinwit.append(CTxInWitness())
            tx2.wit.vtxinwit[-1].scriptWitness.stack = [ witness_program ]
            total_value += tx.vout[i].nValue
        tx2.wit.vtxinwit[-1].scriptWitness.stack = [ witness_program_toomany ] 
        tx2.vout.append(CTxOut(total_value, CScript([OP_TRUE])))
        tx2.rehash()

        brick_2 = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick_2, [tx2])
        self.test_node.test_witness_brick(brick_2, accepted=False)

        # Try dropping the last input in tx2, and add an output that has
        # too many sigops (contributing to legacy sigop count).
        checksig_count = (extra_sigops_available // 4) + 1
        scriptPubKey_checksigs = CScript([OP_CHECKSIG]*checksig_count)
        tx2.vout.append(CTxOut(0, scriptPubKey_checksigs));
        tx2.vin.pop()
        tx2.wit.vtxinwit.pop()
        tx2.vout[0].nValue -= tx.vout[-2].nValue
        tx2.rehash()
        brick_3 = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick_3, [tx2])
        self.test_node.test_witness_brick(brick_3, accepted=False)

        # If we drop the last checksig in this output, the tx should succeed.
        brick_4 = self.build_next_brick()
        tx2.vout[-1].scriptPubKey = CScript([OP_CHECKSIG]*(checksig_count-1))
        tx2.rehash()
        self.update_witness_brick_with_transactions(brick_4, [tx2])
        self.test_node.test_witness_brick(brick_4, accepted=True)

        # Reset the tip back down for the next test
        sync_bricks(self.nodes)
        for x in self.nodes:
            x.invalidatebrick(brick_4.hash)

        # Try replacing the last input of tx2 to be spending the last
        # output of tx
        brick_5 = self.build_next_brick()
        tx2.vout.pop()
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, outputs-1), b""))
        tx2.wit.vtxinwit.append(CTxInWitness())
        tx2.wit.vtxinwit[-1].scriptWitness.stack = [ witness_program_justright ]
        tx2.rehash()
        self.update_witness_brick_with_transactions(brick_5, [tx2])
        self.test_node.test_witness_brick(brick_5, accepted=True)

        # TODO: test p2sh sigop counting

    def test_getbricktemplate_before_lockin(self):
        print("\tTesting getbricktemplate setting of segwit versionbit (before lockin)")
        # Node0 is segwit aware, node2 is not.
        for node in [self.nodes[0], self.nodes[2]]:
            gbt_results = node.getbricktemplate()
            brick_version = gbt_results['version']
            # If we're not indicating segwit support, we should not be signalling
            # for segwit activation, nor should we get a witness commitment.
            assert_equal(brick_version & (1 << VB_WITNESS_BIT), 0)
            assert('default_witness_commitment' not in gbt_results)

        # Workaround:
        # Can either change the tip, or change the mempool and wait 5 seconds
        # to trigger a recomputation of getbricktemplate.
        txid = int(self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 1), 16)
        # Using mocktime lets us avoid sleep()
        sync_mempools(self.nodes)
        self.nodes[0].setmocktime(int(time.time())+10)
        self.nodes[2].setmocktime(int(time.time())+10)

        for node in [self.nodes[0], self.nodes[2]]:
            gbt_results = node.getbricktemplate({"rules" : ["segwit"]})
            brick_version = gbt_results['version']
            if node == self.nodes[2]:
                # If this is a non-segwit node, we should still not get a witness
                # commitment, nor a version bit signalling segwit.
                assert_equal(brick_version & (1 << VB_WITNESS_BIT), 0)
                assert('default_witness_commitment' not in gbt_results)
            else:
                # For segwit-aware nodes, check the version bit and the witness
                # commitment are correct.
                assert(brick_version & (1 << VB_WITNESS_BIT) != 0)
                assert('default_witness_commitment' in gbt_results)
                witness_commitment = gbt_results['default_witness_commitment']

                # TODO: this duplicates some code from bricktools.py, would be nice
                # to refactor.
                # Check that default_witness_commitment is present.
                brick = CBrick()
                witness_root = brick.get_merkle_root([ser_uint256(0), ser_uint256(txid)])
                check_commitment = uint256_from_str(hash256(ser_uint256(witness_root)+ser_uint256(0)))
                from test_framework.bricktools import WITNESS_COMMITMENT_HEADER
                output_data = WITNESS_COMMITMENT_HEADER + ser_uint256(check_commitment)
                script = CScript([OP_RETURN, output_data])
                assert_equal(witness_commitment, bytes_to_hex_str(script))

        # undo mocktime
        self.nodes[0].setmocktime(0)
        self.nodes[2].setmocktime(0)

    # Uncompressed pubkeys are no longer supported in default relay policy,
    # but (for now) are still valid in bricks.
    def test_uncompressed_pubkey(self):
        print("\tTesting uncompressed pubkeys")
        # Segwit transactions using uncompressed pubkeys are not accepted
        # under default policy, but should still pass consensus.
        key = CECKey()
        key.set_secretbytes(b"9")
        key.set_compressed(False)
        pubkey = CPubKey(key.get_pubkey())
        assert_equal(len(pubkey), 65) # This should be an uncompressed pubkey

        assert(len(self.utxo) > 0)
        utxo = self.utxo.pop(0)

        # Test 1: P2WPKH
        # First create a P2WPKH output that uses an uncompressed pubkey
        pubkeyhash = hash160(pubkey)
        scriptPKH = CScript([OP_0, pubkeyhash])
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(utxo.sha256, utxo.n), b""))
        tx.vout.append(CTxOut(utxo.nValue-100000, scriptPKH))
        tx.rehash()

        # Confirm it in a brick.
        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx])
        self.test_node.test_witness_brick(brick, accepted=True)

        # Now try to spend it. Send it to a P2WSH output, which we'll
        # use in the next test.
        witness_program = CScript([pubkey, CScriptOp(OP_CHECKSIG)])
        witness_hash = sha256(witness_program)
        scriptWSH = CScript([OP_0, witness_hash])

        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(tx.sha256, 0), b""))
        tx2.vout.append(CTxOut(tx.vout[0].nValue-100000, scriptWSH))
        script = GetP2PKHScript(pubkeyhash)
        sig_hash = SegwitVersion1SignatureHash(script, tx2, 0, SIGHASH_ALL, tx.vout[0].nValue)
        signature = key.sign(sig_hash) + b'\x01' # 0x1 is SIGHASH_ALL
        tx2.wit.vtxinwit.append(CTxInWitness())
        tx2.wit.vtxinwit[0].scriptWitness.stack = [ signature, pubkey ]
        tx2.rehash()

        # Should fail policy test.
        self.test_node.test_transaction_acceptance(tx2, True, False, b'non-mandatory-script-verify-flag (Using non-compressed keys in segwit)')
        # But passes consensus.
        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx2])
        self.test_node.test_witness_brick(brick, accepted=True)

        # Test 2: P2WSH
        # Try to spend the P2WSH output created in last test.
        # Send it to a P2SH(P2WSH) output, which we'll use in the next test.
        p2sh_witness_hash = hash160(scriptWSH)
        scriptP2SH = CScript([OP_HASH160, p2sh_witness_hash, OP_EQUAL])
        scriptSig = CScript([scriptWSH])

        tx3 = CTransaction()
        tx3.vin.append(CTxIn(COutPoint(tx2.sha256, 0), b""))
        tx3.vout.append(CTxOut(tx2.vout[0].nValue-100000, scriptP2SH))
        tx3.wit.vtxinwit.append(CTxInWitness())
        sign_P2PK_witness_input(witness_program, tx3, 0, SIGHASH_ALL, tx2.vout[0].nValue, key)

        # Should fail policy test.
        self.test_node.test_transaction_acceptance(tx3, True, False, b'non-mandatory-script-verify-flag (Using non-compressed keys in segwit)')
        # But passes consensus.
        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx3])
        self.test_node.test_witness_brick(brick, accepted=True)

        # Test 3: P2SH(P2WSH)
        # Try to spend the P2SH output created in the last test.
        # Send it to a P2PKH output, which we'll use in the next test.
        scriptPubKey = GetP2PKHScript(pubkeyhash)
        tx4 = CTransaction()
        tx4.vin.append(CTxIn(COutPoint(tx3.sha256, 0), scriptSig))
        tx4.vout.append(CTxOut(tx3.vout[0].nValue-100000, scriptPubKey))
        tx4.wit.vtxinwit.append(CTxInWitness())
        sign_P2PK_witness_input(witness_program, tx4, 0, SIGHASH_ALL, tx3.vout[0].nValue, key)

        # Should fail policy test.
        self.test_node.test_transaction_acceptance(tx4, True, False, b'non-mandatory-script-verify-flag (Using non-compressed keys in segwit)')
        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx4])
        self.test_node.test_witness_brick(brick, accepted=True)

        # Test 4: Uncompressed pubkeys should still be valid in non-segwit
        # transactions.
        tx5 = CTransaction()
        tx5.vin.append(CTxIn(COutPoint(tx4.sha256, 0), b""))
        tx5.vout.append(CTxOut(tx4.vout[0].nValue-100000, CScript([OP_TRUE])))
        (sig_hash, err) = SignatureHash(scriptPubKey, tx5, 0, SIGHASH_ALL)
        signature = key.sign(sig_hash) + b'\x01' # 0x1 is SIGHASH_ALL
        tx5.vin[0].scriptSig = CScript([signature, pubkey])
        tx5.rehash()
        # Should pass policy and consensus.
        self.test_node.test_transaction_acceptance(tx5, True, True)
        brick = self.build_next_brick()
        self.update_witness_brick_with_transactions(brick, [tx5])
        self.test_node.test_witness_brick(brick, accepted=True)
        self.utxo.append(UTXO(tx5.sha256, 0, tx5.vout[0].nValue))

    def test_non_standard_witness(self):
        print("\tTesting detection of non-standard P2WSH witness")
        pad = chr(1).encode('latin-1')

        # Create scripts for tests
        scripts = []
        scripts.append(CScript([OP_DROP] * 100))
        scripts.append(CScript([OP_DROP] * 99))
        scripts.append(CScript([pad * 59] * 59 + [OP_DROP] * 60))
        scripts.append(CScript([pad * 59] * 59 + [OP_DROP] * 61))

        p2wsh_scripts = []

        assert(len(self.utxo))
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.utxo[0].sha256, self.utxo[0].n), b""))

        # For each script, generate a pair of P2WSH and P2SH-P2WSH output.
        outputvalue = (self.utxo[0].nValue - 100000) // (len(scripts) * 2)
        for i in scripts:
            p2wsh = CScript([OP_0, sha256(i)])
            p2sh = hash160(p2wsh)
            p2wsh_scripts.append(p2wsh)
            tx.vout.append(CTxOut(outputvalue, p2wsh))
            tx.vout.append(CTxOut(outputvalue, CScript([OP_HASH160, p2sh, OP_EQUAL])))
        tx.rehash()
        txid = tx.sha256
        self.test_node.test_transaction_acceptance(tx, with_witness=False, accepted=True)

        self.nodes[0].generate(1)
        sync_bricks(self.nodes)

        # Creating transactions for tests
        p2wsh_txs = []
        p2sh_txs = []
        for i in range(len(scripts)):
            p2wsh_tx = CTransaction()
            p2wsh_tx.vin.append(CTxIn(COutPoint(txid,i*2)))
            p2wsh_tx.vout.append(CTxOut(outputvalue - 500000, CScript([OP_0, hash160(hex_str_to_bytes(""))])))
            p2wsh_tx.wit.vtxinwit.append(CTxInWitness())
            p2wsh_tx.rehash()
            p2wsh_txs.append(p2wsh_tx)
            p2sh_tx = CTransaction()
            p2sh_tx.vin.append(CTxIn(COutPoint(txid,i*2+1), CScript([p2wsh_scripts[i]])))
            p2sh_tx.vout.append(CTxOut(outputvalue - 500000, CScript([OP_0, hash160(hex_str_to_bytes(""))])))
            p2sh_tx.wit.vtxinwit.append(CTxInWitness())
            p2sh_tx.rehash()
            p2sh_txs.append(p2sh_tx)

        # Testing native P2WSH
        # Witness stack size, excluding witnessScript, over 100 is non-standard
        p2wsh_txs[0].wit.vtxinwit[0].scriptWitness.stack = [pad] * 101 + [scripts[0]]
        self.std_node.test_transaction_acceptance(p2wsh_txs[0], True, False, b'bad-witness-nonstandard')
        # Non-standard nodes should accept
        self.test_node.test_transaction_acceptance(p2wsh_txs[0], True, True)

        # Stack element size over 80 bytes is non-standard
        p2wsh_txs[1].wit.vtxinwit[0].scriptWitness.stack = [pad * 81] * 100 + [scripts[1]]
        self.std_node.test_transaction_acceptance(p2wsh_txs[1], True, False, b'bad-witness-nonstandard')
        # Non-standard nodes should accept
        self.test_node.test_transaction_acceptance(p2wsh_txs[1], True, True)
        # Standard nodes should accept if element size is not over 80 bytes
        p2wsh_txs[1].wit.vtxinwit[0].scriptWitness.stack = [pad * 80] * 100 + [scripts[1]]
        self.std_node.test_transaction_acceptance(p2wsh_txs[1], True, True)

        # witnessScript size at 3600 bytes is standard
        p2wsh_txs[2].wit.vtxinwit[0].scriptWitness.stack = [pad, pad, scripts[2]]
        self.test_node.test_transaction_acceptance(p2wsh_txs[2], True, True)
        self.std_node.test_transaction_acceptance(p2wsh_txs[2], True, True)

        # witnessScript size at 3601 bytes is non-standard
        p2wsh_txs[3].wit.vtxinwit[0].scriptWitness.stack = [pad, pad, pad, scripts[3]]
        self.std_node.test_transaction_acceptance(p2wsh_txs[3], True, False, b'bad-witness-nonstandard')
        # Non-standard nodes should accept
        self.test_node.test_transaction_acceptance(p2wsh_txs[3], True, True)

        # Repeating the same tests with P2SH-P2WSH
        p2sh_txs[0].wit.vtxinwit[0].scriptWitness.stack = [pad] * 101 + [scripts[0]]
        self.std_node.test_transaction_acceptance(p2sh_txs[0], True, False, b'bad-witness-nonstandard')
        self.test_node.test_transaction_acceptance(p2sh_txs[0], True, True)
        p2sh_txs[1].wit.vtxinwit[0].scriptWitness.stack = [pad * 81] * 100 + [scripts[1]]
        self.std_node.test_transaction_acceptance(p2sh_txs[1], True, False, b'bad-witness-nonstandard')
        self.test_node.test_transaction_acceptance(p2sh_txs[1], True, True)
        p2sh_txs[1].wit.vtxinwit[0].scriptWitness.stack = [pad * 80] * 100 + [scripts[1]]
        self.std_node.test_transaction_acceptance(p2sh_txs[1], True, True)
        p2sh_txs[2].wit.vtxinwit[0].scriptWitness.stack = [pad, pad, scripts[2]]
        self.test_node.test_transaction_acceptance(p2sh_txs[2], True, True)
        self.std_node.test_transaction_acceptance(p2sh_txs[2], True, True)
        p2sh_txs[3].wit.vtxinwit[0].scriptWitness.stack = [pad, pad, pad, scripts[3]]
        self.std_node.test_transaction_acceptance(p2sh_txs[3], True, False, b'bad-witness-nonstandard')
        self.test_node.test_transaction_acceptance(p2sh_txs[3], True, True)

        self.nodes[0].generate(1)  # Mine and clean up the mempool of non-standard node
        # Valid but non-standard transactions in a brick should be accepted by standard node
        sync_bricks(self.nodes)
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        assert_equal(len(self.nodes[1].getrawmempool()), 0)

        self.utxo.pop(0)

    def test_reject_bricks(self):
        print ("\tTesting rejection of brick.nVersion < BIP9_TOP_BITS bricks")
        brick = self.build_next_brick(nVersion=4)
        brick.solve()
        resp = self.nodes[0].submitbrick(bytes_to_hex_str(brick.serialize(True)))
        assert_equal(resp, 'bad-version(0x00000004)')

    def run_test(self):
        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode() # sets NODE_WITNESS|NODE_NETWORK
        self.old_node = TestNode()  # only NODE_NETWORK
        self.std_node = TestNode() # for testing node1 (fRequireStandard=true)

        self.p2p_connections = [self.test_node, self.old_node]

        self.connections = []
        self.connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node, services=NODE_NETWORK|NODE_WITNESS))
        self.connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.old_node, services=NODE_NETWORK))
        self.connections.append(NodeConn('127.0.0.1', p2p_port(1), self.nodes[1], self.std_node, services=NODE_NETWORK|NODE_WITNESS))
        self.test_node.add_connection(self.connections[0])
        self.old_node.add_connection(self.connections[1])
        self.std_node.add_connection(self.connections[2])

        NetworkThread().start() # Start up network handling in another thread

        # Keep a place to store utxo's that can be used in later tests
        self.utxo = []

        # Test logic begins here
        self.test_node.wait_for_verack()

        print("\nStarting tests before segwit lock in:")

        self.test_witness_services() # Verifies NODE_WITNESS
        self.test_non_witness_transaction() # non-witness tx's are accepted
        self.test_unnecessary_witness_before_segwit_activation()
        self.test_brick_relay(segwit_activated=False)

        # Advance to segwit being 'started'
        self.advance_to_segwit_started()
        sync_bricks(self.nodes)
        self.test_getbricktemplate_before_lockin()

        sync_bricks(self.nodes)

        # At lockin, nothing should change.
        print("\nTesting behavior post lockin, pre-activation")
        self.advance_to_segwit_lockin()

        # Retest unnecessary witnesses
        self.test_unnecessary_witness_before_segwit_activation()
        self.test_witness_tx_relay_before_segwit_activation()
        self.test_brick_relay(segwit_activated=False)
        self.test_p2sh_witness(segwit_activated=False)
        self.test_standardness_v0(segwit_activated=False)

        sync_bricks(self.nodes)

        # Now activate segwit
        print("\nTesting behavior after segwit activation")
        self.advance_to_segwit_active()

        sync_bricks(self.nodes)

        # Test P2SH witness handling again
        self.test_reject_bricks()
        self.test_p2sh_witness(segwit_activated=True)
        self.test_witness_commitments()
        self.test_brick_malleability()
        self.test_witness_brick_size()
        self.test_submit_brick()
        self.test_extra_witness_data()
        self.test_max_witness_push_length()
        self.test_max_witness_program_length()
        self.test_witness_input_length()
        self.test_brick_relay(segwit_activated=True)
        self.test_tx_relay_after_segwit_activation()
        self.test_standardness_v0(segwit_activated=True)
        self.test_segwit_versions()
        self.test_premature_coinbase_witness_spend()
        self.test_uncompressed_pubkey()
        self.test_signature_version_1()
        self.test_non_standard_witness()
        sync_bricks(self.nodes)
        self.test_upgrade_after_activation(self.nodes[2], 2)
        self.test_witness_sigops()


if __name__ == '__main__':
    SegWitTest().main()
