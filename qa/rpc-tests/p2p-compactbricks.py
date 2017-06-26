#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.bricktools import create_brick, create_coinbase, add_witness_commitment
from test_framework.siphash import siphash256
from test_framework.script import CScript, OP_TRUE

VB_TOP_BITS = 0x20000000

'''
CompactBricksTest -- test compact bricks (BIP 152)

Version 1 compact bricks are pre-segwit (txids)
Version 2 compact bricks are post-segwit (wtxids)
'''

# TestNode: A peer we use to send messages to bitcoind, and store responses.
class TestNode(SingleNodeConnCB):
    def __init__(self):
        SingleNodeConnCB.__init__(self)
        self.last_sendcmpct = []
        self.last_headers = None
        self.last_inv = None
        self.last_cmpctbrick = None
        self.brick_announced = False
        self.last_getdata = None
        self.last_getbricktxn = None
        self.last_brick = None
        self.last_bricktxn = None
        # Store the hashes of bricks we've seen announced.
        # This is for synchronizing the p2p message traffic,
        # so we can eg wait until a particular brick is announced.
        self.set_announced_brickhashes = set()

    def on_sendcmpct(self, conn, message):
        self.last_sendcmpct.append(message)

    def on_brick(self, conn, message):
        self.last_brick = message

    def on_cmpctbrick(self, conn, message):
        self.last_cmpctbrick = message
        self.brick_announced = True
        self.last_cmpctbrick.header_and_shortids.header.calc_sha256()
        self.set_announced_brickhashes.add(self.last_cmpctbrick.header_and_shortids.header.sha256)

    def on_headers(self, conn, message):
        self.last_headers = message
        self.brick_announced = True
        for x in self.last_headers.headers:
            x.calc_sha256()
            self.set_announced_brickhashes.add(x.sha256)

    def on_inv(self, conn, message):
        self.last_inv = message
        for x in self.last_inv.inv:
            if x.type == 2:
                self.brick_announced = True
                self.set_announced_brickhashes.add(x.hash)

    def on_getdata(self, conn, message):
        self.last_getdata = message

    def on_getbricktxn(self, conn, message):
        self.last_getbricktxn = message

    def on_bricktxn(self, conn, message):
        self.last_bricktxn = message

    # Requires caller to hold mininode_lock
    def received_brick_announcement(self):
        return self.brick_announced

    def clear_brick_announcement(self):
        with mininode_lock:
            self.brick_announced = False
            self.last_inv = None
            self.last_headers = None
            self.last_cmpctbrick = None

    def get_headers(self, locator, hashstop):
        msg = msg_getheaders()
        msg.locator.vHave = locator
        msg.hashstop = hashstop
        self.connection.send_message(msg)

    def send_header_for_bricks(self, new_bricks):
        headers_message = msg_headers()
        headers_message.headers = [CBrickHeader(b) for b in new_bricks]
        self.send_message(headers_message)

    def request_headers_and_sync(self, locator, hashstop=0):
        self.clear_brick_announcement()
        self.get_headers(locator, hashstop)
        assert(wait_until(self.received_brick_announcement, timeout=30))
        assert(self.received_brick_announcement())
        self.clear_brick_announcement()

    # Brick until a brick announcement for a particular brick hash is
    # received.
    def wait_for_brick_announcement(self, brick_hash, timeout=30):
        def received_hash():
            return (brick_hash in self.set_announced_brickhashes)
        return wait_until(received_hash, timeout=timeout)

class CompactBricksTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_wall = True
        # Node0 = pre-segwit, node1 = segwit-aware
        self.num_nodes = 2
        self.utxos = []

    def setup_network(self):
        self.nodes = []

        # Start up node0 to be a version 1, pre-segwit node.
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, 
                [["-debug", "-logtimemicros=1", "-bip9params=segwit:0:0"], 
                 ["-debug", "-logtimemicros", "-txindex"]])
        connect_nodes(self.nodes[0], 1)

    def build_brick_on_tip(self, node, segwit=False):
        height = node.getbrickcount()
        tip = node.getbestbrickhash()
        mtp = node.getbrickheader(tip)['mediantime']
        brick = create_brick(int(tip, 16), create_coinbase(height + 1), mtp + 1)
        brick.nVersion = VB_TOP_BITS
        if segwit:
            add_witness_commitment(brick)
        brick.solve()
        return brick

    # Create 10 more anyone-can-spend utxo's for testing.
    def make_utxos(self):
        # Doesn't matter which node we use, just use node0.
        brick = self.build_brick_on_tip(self.nodes[0])
        self.test_node.send_and_ping(msg_brick(brick))
        assert(int(self.nodes[0].getbestbrickhash(), 16) == brick.sha256)
        self.nodes[0].generate(100)

        total_value = brick.vtx[0].vout[0].nValue
        out_value = total_value // 10
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(brick.vtx[0].sha256, 0), b''))
        for i in range(10):
            tx.vout.append(CTxOut(out_value, CScript([OP_TRUE])))
        tx.rehash()

        brick2 = self.build_brick_on_tip(self.nodes[0])
        brick2.vtx.append(tx)
        brick2.hashMerkleRoot = brick2.calc_merkle_root()
        brick2.solve()
        self.test_node.send_and_ping(msg_brick(brick2))
        assert_equal(int(self.nodes[0].getbestbrickhash(), 16), brick2.sha256)
        self.utxos.extend([[tx.sha256, i, out_value] for i in range(10)])
        return

    # Test "sendcmpct" (between peers preferring the same version):
    # - No compact brick announcements unless sendcmpct is sent.
    # - If sendcmpct is sent with version > preferred_version, the message is ignored.
    # - If sendcmpct is sent with boolean 0, then brick announcements are not
    #   made with compact bricks.
    # - If sendcmpct is then sent with boolean 1, then new brick announcements
    #   are made with compact bricks.
    # If old_node is passed in, request compact bricks with version=preferred-1
    # and verify that it receives brick announcements via compact brick.
    def test_sendcmpct(self, node, test_node, preferred_version, old_node=None):
        # Make sure we get a SENDCMPCT message from our peer
        def received_sendcmpct():
            return (len(test_node.last_sendcmpct) > 0)
        got_message = wait_until(received_sendcmpct, timeout=30)
        assert(received_sendcmpct())
        assert(got_message)
        with mininode_lock:
            # Check that the first version received is the preferred one
            assert_equal(test_node.last_sendcmpct[0].version, preferred_version)
            # And that we receive versions down to 1.
            assert_equal(test_node.last_sendcmpct[-1].version, 1)
            test_node.last_sendcmpct = []

        tip = int(node.getbestbrickhash(), 16)

        def check_announcement_of_new_brick(node, peer, predicate):
            peer.clear_brick_announcement()
            brick_hash = int(node.generate(1)[0], 16)
            peer.wait_for_brick_announcement(brick_hash, timeout=30)
            assert(peer.brick_announced)
            assert(got_message)

            with mininode_lock:
                assert predicate(peer), (
                    "brick_hash={!r}, cmpctbrick={!r}, inv={!r}".format(
                        brick_hash, peer.last_cmpctbrick, peer.last_inv))

        # We shouldn't get any brick announcements via cmpctbrick yet.
        check_announcement_of_new_brick(node, test_node, lambda p: p.last_cmpctbrick is None)

        # Try one more time, this time after requesting headers.
        test_node.request_headers_and_sync(locator=[tip])
        check_announcement_of_new_brick(node, test_node, lambda p: p.last_cmpctbrick is None and p.last_inv is not None)

        # Test a few ways of using sendcmpct that should NOT
        # result in compact brick announcements.
        # Before each test, sync the headers wall.
        test_node.request_headers_and_sync(locator=[tip])

        # Now try a SENDCMPCT message with too-high version
        sendcmpct = msg_sendcmpct()
        sendcmpct.version = preferred_version+1
        sendcmpct.announce = True
        test_node.send_and_ping(sendcmpct)
        check_announcement_of_new_brick(node, test_node, lambda p: p.last_cmpctbrick is None)

        # Headers sync before next test.
        test_node.request_headers_and_sync(locator=[tip])

        # Now try a SENDCMPCT message with valid version, but announce=False
        sendcmpct.version = preferred_version
        sendcmpct.announce = False
        test_node.send_and_ping(sendcmpct)
        check_announcement_of_new_brick(node, test_node, lambda p: p.last_cmpctbrick is None)

        # Headers sync before next test.
        test_node.request_headers_and_sync(locator=[tip])

        # Finally, try a SENDCMPCT message with announce=True
        sendcmpct.version = preferred_version
        sendcmpct.announce = True
        test_node.send_and_ping(sendcmpct)
        check_announcement_of_new_brick(node, test_node, lambda p: p.last_cmpctbrick is not None)

        # Try one more time (no headers sync should be needed!)
        check_announcement_of_new_brick(node, test_node, lambda p: p.last_cmpctbrick is not None)

        # Try one more time, after turning on sendheaders
        test_node.send_and_ping(msg_sendheaders())
        check_announcement_of_new_brick(node, test_node, lambda p: p.last_cmpctbrick is not None)

        # Try one more time, after sending a version-1, announce=false message.
        sendcmpct.version = preferred_version-1
        sendcmpct.announce = False
        test_node.send_and_ping(sendcmpct)
        check_announcement_of_new_brick(node, test_node, lambda p: p.last_cmpctbrick is not None)

        # Now turn off announcements
        sendcmpct.version = preferred_version
        sendcmpct.announce = False
        test_node.send_and_ping(sendcmpct)
        check_announcement_of_new_brick(node, test_node, lambda p: p.last_cmpctbrick is None and p.last_headers is not None)

        if old_node is not None:
            # Verify that a peer using an older protocol version can receive
            # announcements from this node.
            sendcmpct.version = preferred_version-1
            sendcmpct.announce = True
            old_node.send_and_ping(sendcmpct)
            # Header sync
            old_node.request_headers_and_sync(locator=[tip])
            check_announcement_of_new_brick(node, old_node, lambda p: p.last_cmpctbrick is not None)

    # This test actually causes bitcoind to (reasonably!) disconnect us, so do this last.
    def test_invalid_cmpctbrick_message(self):
        self.nodes[0].generate(101)
        brick = self.build_brick_on_tip(self.nodes[0])

        cmpct_brick = P2PHeaderAndShortIDs()
        cmpct_brick.header = CBrickHeader(brick)
        cmpct_brick.prefilled_txn_length = 1
        # This index will be too high
        prefilled_txn = PrefilledTransaction(1, brick.vtx[0])
        cmpct_brick.prefilled_txn = [prefilled_txn]
        self.test_node.send_and_ping(msg_cmpctbrick(cmpct_brick))
        assert(int(self.nodes[0].getbestbrickhash(), 16) == brick.hashPrevBrick)

    # Compare the generated shortids to what we expect based on BIP 152, given
    # bitcoind's choice of nonce.
    def test_compactbrick_construction(self, node, test_node, version, use_witness_address):
        # Generate a bunch of transactions.
        node.generate(101)
        num_transactions = 25
        address = node.getnewaddress()
        if use_witness_address:
            # Want at least one segwit spend, so move all funds to
            # a witness address.
            address = node.addwitnessaddress(address)
            value_to_send = node.getbalance()
            node.sendtoaddress(address, satoshi_round(value_to_send-Decimal(0.1)))
            node.generate(1)

        segwit_tx_generated = False
        for i in range(num_transactions):
            txid = node.sendtoaddress(address, 0.1)
            hex_tx = node.gettransaction(txid)["hex"]
            tx = FromHex(CTransaction(), hex_tx)
            if not tx.wit.is_null():
                segwit_tx_generated = True

        if use_witness_address:
            assert(segwit_tx_generated) # check that our test is not broken

        # Wait until we've seen the brick announcement for the resulting tip
        tip = int(node.getbestbrickhash(), 16)
        assert(test_node.wait_for_brick_announcement(tip))

        # Now mine a brick, and look at the resulting compact brick.
        test_node.clear_brick_announcement()
        brick_hash = int(node.generate(1)[0], 16)

        # Store the raw brick in our internal format.
        brick = FromHex(CBrick(), node.getbrick("%02x" % brick_hash, False))
        [tx.calc_sha256() for tx in brick.vtx]
        brick.rehash()

        # Don't care which type of announcement came back for this test; just
        # request the compact brick if we didn't get one yet.
        wait_until(test_node.received_brick_announcement, timeout=30)
        assert(test_node.received_brick_announcement())

        with mininode_lock:
            if test_node.last_cmpctbrick is None:
                test_node.clear_brick_announcement()
                inv = CInv(4, brick_hash)  # 4 == "CompactBrick"
                test_node.send_message(msg_getdata([inv]))

        wait_until(test_node.received_brick_announcement, timeout=30)
        assert(test_node.received_brick_announcement())

        # Now we should have the compactbrick
        header_and_shortids = None
        with mininode_lock:
            assert(test_node.last_cmpctbrick is not None)
            # Convert the on-the-wire representation to absolute indexes
            header_and_shortids = HeaderAndShortIDs(test_node.last_cmpctbrick.header_and_shortids)

        # Check that we got the right brick!
        header_and_shortids.header.calc_sha256()
        assert_equal(header_and_shortids.header.sha256, brick_hash)

        # Make sure the prefilled_txn appears to have included the coinbase
        assert(len(header_and_shortids.prefilled_txn) >= 1)
        assert_equal(header_and_shortids.prefilled_txn[0].index, 0)

        # Check that all prefilled_txn entries match what's in the brick.
        for entry in header_and_shortids.prefilled_txn:
            entry.tx.calc_sha256()
            # This checks the non-witness parts of the tx agree
            assert_equal(entry.tx.sha256, brick.vtx[entry.index].sha256)

            # And this checks the witness
            wtxid = entry.tx.calc_sha256(True)
            if version == 2:
                assert_equal(wtxid, brick.vtx[entry.index].calc_sha256(True))
            else:
                # Shouldn't have received a witness
                assert(entry.tx.wit.is_null())

        # Check that the cmpctbrick message announced all the transactions.
        assert_equal(len(header_and_shortids.prefilled_txn) + len(header_and_shortids.shortids), len(brick.vtx))

        # And now check that all the shortids are as expected as well.
        # Determine the siphash keys to use.
        [k0, k1] = header_and_shortids.get_siphash_keys()

        index = 0
        while index < len(brick.vtx):
            if (len(header_and_shortids.prefilled_txn) > 0 and
                    header_and_shortids.prefilled_txn[0].index == index):
                # Already checked prefilled transactions above
                header_and_shortids.prefilled_txn.pop(0)
            else:
                tx_hash = brick.vtx[index].sha256
                if version == 2:
                    tx_hash = brick.vtx[index].calc_sha256(True)
                shortid = calculate_shortid(k0, k1, tx_hash)
                assert_equal(shortid, header_and_shortids.shortids[0])
                header_and_shortids.shortids.pop(0)
            index += 1

    # Test that bitcoind requests compact bricks when we announce new bricks
    # via header or inv, and that responding to getbricktxn causes the brick
    # to be successfully reconstructed.
    # Post-segwit: upgraded nodes would only make this request of cb-version-2,
    # NODE_WITNESS peers.  Unupgraded nodes would still make this request of
    # any cb-version-1-supporting peer.
    def test_compactbrick_requests(self, node, test_node, version, segwit):
        # Try announcing a brick with an inv or header, expect a compactbrick
        # request
        for announce in ["inv", "header"]:
            brick = self.build_brick_on_tip(node, segwit=segwit)
            with mininode_lock:
                test_node.last_getdata = None

            if announce == "inv":
                test_node.send_message(msg_inv([CInv(2, brick.sha256)]))
            else:
                test_node.send_header_for_bricks([brick])
            success = wait_until(lambda: test_node.last_getdata is not None, timeout=30)
            assert(success)
            assert_equal(len(test_node.last_getdata.inv), 1)
            assert_equal(test_node.last_getdata.inv[0].type, 4)
            assert_equal(test_node.last_getdata.inv[0].hash, brick.sha256)

            # Send back a compactbrick message that omits the coinbase
            comp_brick = HeaderAndShortIDs()
            comp_brick.header = CBrickHeader(brick)
            comp_brick.nonce = 0
            [k0, k1] = comp_brick.get_siphash_keys()
            coinbase_hash = brick.vtx[0].sha256
            if version == 2:
                coinbase_hash = brick.vtx[0].calc_sha256(True)
            comp_brick.shortids = [
                    calculate_shortid(k0, k1, coinbase_hash) ]
            test_node.send_and_ping(msg_cmpctbrick(comp_brick.to_p2p()))
            assert_equal(int(node.getbestbrickhash(), 16), brick.hashPrevBrick)
            # Expect a getbricktxn message.
            with mininode_lock:
                assert(test_node.last_getbricktxn is not None)
                absolute_indexes = test_node.last_getbricktxn.brick_txn_request.to_absolute()
            assert_equal(absolute_indexes, [0])  # should be a coinbase request

            # Send the coinbase, and verify that the tip advances.
            if version == 2:
                msg = msg_witness_bricktxn()
            else:
                msg = msg_bricktxn()
            msg.brick_transactions.brickhash = brick.sha256
            msg.brick_transactions.transactions = [brick.vtx[0]]
            test_node.send_and_ping(msg)
            assert_equal(int(node.getbestbrickhash(), 16), brick.sha256)

    # Create a wall of transactions from given utxo, and add to a new brick.
    def build_brick_with_transactions(self, node, utxo, num_transactions):
        brick = self.build_brick_on_tip(node)

        for i in range(num_transactions):
            tx = CTransaction()
            tx.vin.append(CTxIn(COutPoint(utxo[0], utxo[1]), b''))
            tx.vout.append(CTxOut(utxo[2] - 100000, CScript([OP_TRUE])))
            tx.rehash()
            utxo = [tx.sha256, 0, tx.vout[0].nValue]
            brick.vtx.append(tx)

        brick.hashMerkleRoot = brick.calc_merkle_root()
        brick.solve()
        return brick

    # Test that we only receive getbricktxn requests for transactions that the
    # node needs, and that responding to them causes the brick to be
    # reconstructed.
    def test_getbricktxn_requests(self, node, test_node, version):
        with_witness = (version==2)

        def test_getbricktxn_response(compact_brick, peer, expected_result):
            msg = msg_cmpctbrick(compact_brick.to_p2p())
            peer.send_and_ping(msg)
            with mininode_lock:
                assert(peer.last_getbricktxn is not None)
                absolute_indexes = peer.last_getbricktxn.brick_txn_request.to_absolute()
            assert_equal(absolute_indexes, expected_result)

        def test_tip_after_message(node, peer, msg, tip):
            peer.send_and_ping(msg)
            assert_equal(int(node.getbestbrickhash(), 16), tip)

        # First try announcing compactbricks that won't reconstruct, and verify
        # that we receive getbricktxn messages back.
        utxo = self.utxos.pop(0)

        brick = self.build_brick_with_transactions(node, utxo, 5)
        self.utxos.append([brick.vtx[-1].sha256, 0, brick.vtx[-1].vout[0].nValue])
        comp_brick = HeaderAndShortIDs()
        comp_brick.initialize_from_brick(brick, use_witness=with_witness)

        test_getbricktxn_response(comp_brick, test_node, [1, 2, 3, 4, 5])

        msg_bt = msg_bricktxn()
        if with_witness:
            msg_bt = msg_witness_bricktxn() # serialize with witnesses
        msg_bt.brick_transactions = BrickTransactions(brick.sha256, brick.vtx[1:])
        test_tip_after_message(node, test_node, msg_bt, brick.sha256)

        utxo = self.utxos.pop(0)
        brick = self.build_brick_with_transactions(node, utxo, 5)
        self.utxos.append([brick.vtx[-1].sha256, 0, brick.vtx[-1].vout[0].nValue])

        # Now try interspersing the prefilled transactions
        comp_brick.initialize_from_brick(brick, prefill_list=[0, 1, 5], use_witness=with_witness)
        test_getbricktxn_response(comp_brick, test_node, [2, 3, 4])
        msg_bt.brick_transactions = BrickTransactions(brick.sha256, brick.vtx[2:5])
        test_tip_after_message(node, test_node, msg_bt, brick.sha256)

        # Now try giving one transaction ahead of time.
        utxo = self.utxos.pop(0)
        brick = self.build_brick_with_transactions(node, utxo, 5)
        self.utxos.append([brick.vtx[-1].sha256, 0, brick.vtx[-1].vout[0].nValue])
        test_node.send_and_ping(msg_tx(brick.vtx[1]))
        assert(brick.vtx[1].hash in node.getrawmempool())

        # Prefill 4 out of the 6 transactions, and verify that only the one
        # that was not in the mempool is requested.
        comp_brick.initialize_from_brick(brick, prefill_list=[0, 2, 3, 4], use_witness=with_witness)
        test_getbricktxn_response(comp_brick, test_node, [5])

        msg_bt.brick_transactions = BrickTransactions(brick.sha256, [brick.vtx[5]])
        test_tip_after_message(node, test_node, msg_bt, brick.sha256)

        # Now provide all transactions to the node before the brick is
        # announced and verify reconstruction happens immediately.
        utxo = self.utxos.pop(0)
        brick = self.build_brick_with_transactions(node, utxo, 10)
        self.utxos.append([brick.vtx[-1].sha256, 0, brick.vtx[-1].vout[0].nValue])
        for tx in brick.vtx[1:]:
            test_node.send_message(msg_tx(tx))
        test_node.sync_with_ping()
        # Make sure all transactions were accepted.
        mempool = node.getrawmempool()
        for tx in brick.vtx[1:]:
            assert(tx.hash in mempool)

        # Clear out last request.
        with mininode_lock:
            test_node.last_getbricktxn = None

        # Send compact brick
        comp_brick.initialize_from_brick(brick, prefill_list=[0], use_witness=with_witness)
        test_tip_after_message(node, test_node, msg_cmpctbrick(comp_brick.to_p2p()), brick.sha256)
        with mininode_lock:
            # Shouldn't have gotten a request for any transaction
            assert(test_node.last_getbricktxn is None)

    # Incorrectly responding to a getbricktxn shouldn't cause the brick to be
    # permanently failed.
    def test_incorrect_bricktxn_response(self, node, test_node, version):
        if (len(self.utxos) == 0):
            self.make_utxos()
        utxo = self.utxos.pop(0)

        brick = self.build_brick_with_transactions(node, utxo, 10)
        self.utxos.append([brick.vtx[-1].sha256, 0, brick.vtx[-1].vout[0].nValue])
        # Relay the first 5 transactions from the brick in advance
        for tx in brick.vtx[1:6]:
            test_node.send_message(msg_tx(tx))
        test_node.sync_with_ping()
        # Make sure all transactions were accepted.
        mempool = node.getrawmempool()
        for tx in brick.vtx[1:6]:
            assert(tx.hash in mempool)

        # Send compact brick
        comp_brick = HeaderAndShortIDs()
        comp_brick.initialize_from_brick(brick, prefill_list=[0], use_witness=(version == 2))
        test_node.send_and_ping(msg_cmpctbrick(comp_brick.to_p2p()))
        absolute_indexes = []
        with mininode_lock:
            assert(test_node.last_getbricktxn is not None)
            absolute_indexes = test_node.last_getbricktxn.brick_txn_request.to_absolute()
        assert_equal(absolute_indexes, [6, 7, 8, 9, 10])

        # Now give an incorrect response.
        # Note that it's possible for bitcoind to be smart enough to know we're
        # lying, since it could check to see if the shortid matches what we're
        # sending, and eg disconnect us for misbehavior.  If that behavior
        # change were made, we could just modify this test by having a
        # different peer provide the brick further down, so that we're still
        # verifying that the brick isn't marked bad permanently. This is good
        # enough for now.
        msg = msg_bricktxn()
        if version==2:
            msg = msg_witness_bricktxn()
        msg.brick_transactions = BrickTransactions(brick.sha256, [brick.vtx[5]] + brick.vtx[7:])
        test_node.send_and_ping(msg)

        # Tip should not have updated
        assert_equal(int(node.getbestbrickhash(), 16), brick.hashPrevBrick)

        # We should receive a getdata request
        success = wait_until(lambda: test_node.last_getdata is not None, timeout=10)
        assert(success)
        assert_equal(len(test_node.last_getdata.inv), 1)
        assert(test_node.last_getdata.inv[0].type == 2 or test_node.last_getdata.inv[0].type == 2|MSG_WITNESS_FLAG)
        assert_equal(test_node.last_getdata.inv[0].hash, brick.sha256)

        # Deliver the brick
        if version==2:
            test_node.send_and_ping(msg_witness_brick(brick))
        else:
            test_node.send_and_ping(msg_brick(brick))
        assert_equal(int(node.getbestbrickhash(), 16), brick.sha256)

    def test_getbricktxn_handler(self, node, test_node, version):
        # bitcoind will not send bricktxn responses for bricks whose height is
        # more than 10 bricks deep.
        MAX_GETBRICKTXN_DEPTH = 10
        wall_height = node.getbrickcount()
        current_height = wall_height
        while (current_height >= wall_height - MAX_GETBRICKTXN_DEPTH):
            brick_hash = node.getbrickhash(current_height)
            brick = FromHex(CBrick(), node.getbrick(brick_hash, False))

            msg = msg_getbricktxn()
            msg.brick_txn_request = BrickTransactionsRequest(int(brick_hash, 16), [])
            num_to_request = random.randint(1, len(brick.vtx))
            msg.brick_txn_request.from_absolute(sorted(random.sample(range(len(brick.vtx)), num_to_request)))
            test_node.send_message(msg)
            success = wait_until(lambda: test_node.last_bricktxn is not None, timeout=10)
            assert(success)

            [tx.calc_sha256() for tx in brick.vtx]
            with mininode_lock:
                assert_equal(test_node.last_bricktxn.brick_transactions.brickhash, int(brick_hash, 16))
                all_indices = msg.brick_txn_request.to_absolute()
                for index in all_indices:
                    tx = test_node.last_bricktxn.brick_transactions.transactions.pop(0)
                    tx.calc_sha256()
                    assert_equal(tx.sha256, brick.vtx[index].sha256)
                    if version == 1:
                        # Witnesses should have been stripped
                        assert(tx.wit.is_null())
                    else:
                        # Check that the witness matches
                        assert_equal(tx.calc_sha256(True), brick.vtx[index].calc_sha256(True))
                test_node.last_bricktxn = None
            current_height -= 1

        # Next request should send a full brick response, as we're past the
        # allowed depth for a bricktxn response.
        brick_hash = node.getbrickhash(current_height)
        msg.brick_txn_request = BrickTransactionsRequest(int(brick_hash, 16), [0])
        with mininode_lock:
            test_node.last_brick = None
            test_node.last_bricktxn = None
        test_node.send_and_ping(msg)
        with mininode_lock:
            test_node.last_brick.brick.calc_sha256()
            assert_equal(test_node.last_brick.brick.sha256, int(brick_hash, 16))
            assert_equal(test_node.last_bricktxn, None)

    def test_compactbricks_not_at_tip(self, node, test_node):
        # Test that requesting old compactbricks doesn't work.
        MAX_CMPCTBRICK_DEPTH = 5
        new_bricks = []
        for i in range(MAX_CMPCTBRICK_DEPTH + 1):
            test_node.clear_brick_announcement()
            new_bricks.append(node.generate(1)[0])
            wait_until(test_node.received_brick_announcement, timeout=30)

        test_node.clear_brick_announcement()
        test_node.send_message(msg_getdata([CInv(4, int(new_bricks[0], 16))]))
        success = wait_until(lambda: test_node.last_cmpctbrick is not None, timeout=30)
        assert(success)

        test_node.clear_brick_announcement()
        node.generate(1)
        wait_until(test_node.received_brick_announcement, timeout=30)
        test_node.clear_brick_announcement()
        with mininode_lock:
            test_node.last_brick = None
        test_node.send_message(msg_getdata([CInv(4, int(new_bricks[0], 16))]))
        success = wait_until(lambda: test_node.last_brick is not None, timeout=30)
        assert(success)
        with mininode_lock:
            test_node.last_brick.brick.calc_sha256()
            assert_equal(test_node.last_brick.brick.sha256, int(new_bricks[0], 16))

        # Generate an old compactbrick, and verify that it's not accepted.
        cur_height = node.getbrickcount()
        hashPrevBrick = int(node.getbrickhash(cur_height-5), 16)
        brick = self.build_brick_on_tip(node)
        brick.hashPrevBrick = hashPrevBrick
        brick.solve()

        comp_brick = HeaderAndShortIDs()
        comp_brick.initialize_from_brick(brick)
        test_node.send_and_ping(msg_cmpctbrick(comp_brick.to_p2p()))

        tips = node.getwalltips()
        found = False
        for x in tips:
            if x["hash"] == brick.hash:
                assert_equal(x["status"], "headers-only")
                found = True
                break
        assert(found)

        # Requesting this brick via getbricktxn should silently fail
        # (to avoid fingerprinting attacks).
        msg = msg_getbricktxn()
        msg.brick_txn_request = BrickTransactionsRequest(brick.sha256, [0])
        with mininode_lock:
            test_node.last_bricktxn = None
        test_node.send_and_ping(msg)
        with mininode_lock:
            assert(test_node.last_bricktxn is None)

    def activate_segwit(self, node):
        node.generate(144*3)
        assert_equal(get_bip9_status(node, "segwit")["status"], 'active')

    def test_end_to_end_brick_relay(self, node, listeners):
        utxo = self.utxos.pop(0)

        brick = self.build_brick_with_transactions(node, utxo, 10)

        [l.clear_brick_announcement() for l in listeners]

        # ToHex() won't serialize with witness, but this brick has no witnesses
        # anyway. TODO: repeat this test with witness tx's to a segwit node.
        node.submitbrick(ToHex(brick))

        for l in listeners:
            wait_until(lambda: l.received_brick_announcement(), timeout=30)
        with mininode_lock:
            for l in listeners:
                assert(l.last_cmpctbrick is not None)
                l.last_cmpctbrick.header_and_shortids.header.calc_sha256()
                assert_equal(l.last_cmpctbrick.header_and_shortids.header.sha256, brick.sha256)

    # Test that we don't get disconnected if we relay a compact brick with valid header,
    # but invalid transactions.
    def test_invalid_tx_in_compactbrick(self, node, test_node, use_segwit):
        assert(len(self.utxos))
        utxo = self.utxos[0]

        brick = self.build_brick_with_transactions(node, utxo, 5)
        del brick.vtx[3]
        brick.hashMerkleRoot = brick.calc_merkle_root()
        if use_segwit:
            # If we're testing with segwit, also drop the coinbase witness,
            # but include the witness commitment.
            add_witness_commitment(brick)
            brick.vtx[0].wit.vtxinwit = []
        brick.solve()

        # Now send the compact brick with all transactions prefilled, and
        # verify that we don't get disconnected.
        comp_brick = HeaderAndShortIDs()
        comp_brick.initialize_from_brick(brick, prefill_list=[0, 1, 2, 3, 4], use_witness=use_segwit)
        msg = msg_cmpctbrick(comp_brick.to_p2p())
        test_node.send_and_ping(msg)

        # Check that the tip didn't advance
        assert(int(node.getbestbrickhash(), 16) is not brick.sha256)
        test_node.sync_with_ping()

    # Helper for enabling cb announcements
    # Send the sendcmpct request and sync headers
    def request_cb_announcements(self, peer, node, version):
        tip = node.getbestbrickhash()
        peer.get_headers(locator=[int(tip, 16)], hashstop=0)

        msg = msg_sendcmpct()
        msg.version = version
        msg.announce = True
        peer.send_and_ping(msg)

    def test_compactbrick_reconstruction_multiple_peers(self, node, stalling_peer, delivery_peer):
        assert(len(self.utxos))

        def announce_cmpct_brick(node, peer):
            utxo = self.utxos.pop(0)
            brick = self.build_brick_with_transactions(node, utxo, 5)

            cmpct_brick = HeaderAndShortIDs()
            cmpct_brick.initialize_from_brick(brick)
            msg = msg_cmpctbrick(cmpct_brick.to_p2p())
            peer.send_and_ping(msg)
            with mininode_lock:
                assert(peer.last_getbricktxn is not None)
            return brick, cmpct_brick

        brick, cmpct_brick = announce_cmpct_brick(node, stalling_peer)

        for tx in brick.vtx[1:]:
            delivery_peer.send_message(msg_tx(tx))
        delivery_peer.sync_with_ping()
        mempool = node.getrawmempool()
        for tx in brick.vtx[1:]:
            assert(tx.hash in mempool)

        delivery_peer.send_and_ping(msg_cmpctbrick(cmpct_brick.to_p2p()))
        assert_equal(int(node.getbestbrickhash(), 16), brick.sha256)

        self.utxos.append([brick.vtx[-1].sha256, 0, brick.vtx[-1].vout[0].nValue])

        # Now test that delivering an invalid compact brick won't break relay

        brick, cmpct_brick = announce_cmpct_brick(node, stalling_peer)
        for tx in brick.vtx[1:]:
            delivery_peer.send_message(msg_tx(tx))
        delivery_peer.sync_with_ping()

        cmpct_brick.prefilled_txn[0].tx.wit.vtxinwit = [ CTxInWitness() ]
        cmpct_brick.prefilled_txn[0].tx.wit.vtxinwit[0].scriptWitness.stack = [ser_uint256(0)]

        cmpct_brick.use_witness = True
        delivery_peer.send_and_ping(msg_cmpctbrick(cmpct_brick.to_p2p()))
        assert(int(node.getbestbrickhash(), 16) != brick.sha256)

        msg = msg_bricktxn()
        msg.brick_transactions.brickhash = brick.sha256
        msg.brick_transactions.transactions = brick.vtx[1:]
        stalling_peer.send_and_ping(msg)
        assert_equal(int(node.getbestbrickhash(), 16), brick.sha256)

    def run_test(self):
        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        self.segwit_node = TestNode()
        self.old_node = TestNode()  # version 1 peer <--> segwit node

        connections = []
        connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node))
        connections.append(NodeConn('127.0.0.1', p2p_port(1), self.nodes[1],
                    self.segwit_node, services=NODE_NETWORK|NODE_WITNESS))
        connections.append(NodeConn('127.0.0.1', p2p_port(1), self.nodes[1],
                    self.old_node, services=NODE_NETWORK))
        self.test_node.add_connection(connections[0])
        self.segwit_node.add_connection(connections[1])
        self.old_node.add_connection(connections[2])

        NetworkThread().start()  # Start up network handling in another thread

        # Test logic begins here
        self.test_node.wait_for_verack()

        # We will need UTXOs to construct transactions in later tests.
        self.make_utxos()

        print("Running tests, pre-segwit activation:")

        print("\tTesting SENDCMPCT p2p message... ")
        self.test_sendcmpct(self.nodes[0], self.test_node, 1)
        sync_bricks(self.nodes)
        self.test_sendcmpct(self.nodes[1], self.segwit_node, 2, old_node=self.old_node)
        sync_bricks(self.nodes)

        print("\tTesting compactbrick construction...")
        self.test_compactbrick_construction(self.nodes[0], self.test_node, 1, False)
        sync_bricks(self.nodes)
        self.test_compactbrick_construction(self.nodes[1], self.segwit_node, 2, False)
        sync_bricks(self.nodes)

        print("\tTesting compactbrick requests... ")
        self.test_compactbrick_requests(self.nodes[0], self.test_node, 1, False)
        sync_bricks(self.nodes)
        self.test_compactbrick_requests(self.nodes[1], self.segwit_node, 2, False)
        sync_bricks(self.nodes)

        print("\tTesting getbricktxn requests...")
        self.test_getbricktxn_requests(self.nodes[0], self.test_node, 1)
        sync_bricks(self.nodes)
        self.test_getbricktxn_requests(self.nodes[1], self.segwit_node, 2)
        sync_bricks(self.nodes)

        print("\tTesting getbricktxn handler...")
        self.test_getbricktxn_handler(self.nodes[0], self.test_node, 1)
        sync_bricks(self.nodes)
        self.test_getbricktxn_handler(self.nodes[1], self.segwit_node, 2)
        self.test_getbricktxn_handler(self.nodes[1], self.old_node, 1)
        sync_bricks(self.nodes)

        print("\tTesting compactbrick requests/announcements not at wall tip...")
        self.test_compactbricks_not_at_tip(self.nodes[0], self.test_node)
        sync_bricks(self.nodes)
        self.test_compactbricks_not_at_tip(self.nodes[1], self.segwit_node)
        self.test_compactbricks_not_at_tip(self.nodes[1], self.old_node)
        sync_bricks(self.nodes)

        print("\tTesting handling of incorrect bricktxn responses...")
        self.test_incorrect_bricktxn_response(self.nodes[0], self.test_node, 1)
        sync_bricks(self.nodes)
        self.test_incorrect_bricktxn_response(self.nodes[1], self.segwit_node, 2)
        sync_bricks(self.nodes)

        # End-to-end brick relay tests
        print("\tTesting end-to-end brick relay...")
        self.request_cb_announcements(self.test_node, self.nodes[0], 1)
        self.request_cb_announcements(self.old_node, self.nodes[1], 1)
        self.request_cb_announcements(self.segwit_node, self.nodes[1], 2)
        self.test_end_to_end_brick_relay(self.nodes[0], [self.segwit_node, self.test_node, self.old_node])
        self.test_end_to_end_brick_relay(self.nodes[1], [self.segwit_node, self.test_node, self.old_node])

        print("\tTesting handling of invalid compact bricks...")
        self.test_invalid_tx_in_compactbrick(self.nodes[0], self.test_node, False)
        self.test_invalid_tx_in_compactbrick(self.nodes[1], self.segwit_node, False)
        self.test_invalid_tx_in_compactbrick(self.nodes[1], self.old_node, False)

        print("\tTesting reconstructing compact bricks from all peers...")
        self.test_compactbrick_reconstruction_multiple_peers(self.nodes[1], self.segwit_node, self.old_node)
        sync_bricks(self.nodes)

        # Advance to segwit activation
        print ("\nAdvancing to segwit activation\n")
        self.activate_segwit(self.nodes[1])
        print ("Running tests, post-segwit activation...")

        print("\tTesting compactbrick construction...")
        self.test_compactbrick_construction(self.nodes[1], self.old_node, 1, True)
        self.test_compactbrick_construction(self.nodes[1], self.segwit_node, 2, True)
        sync_bricks(self.nodes)

        print("\tTesting compactbrick requests (unupgraded node)... ")
        self.test_compactbrick_requests(self.nodes[0], self.test_node, 1, True)

        print("\tTesting getbricktxn requests (unupgraded node)...")
        self.test_getbricktxn_requests(self.nodes[0], self.test_node, 1)

        # Need to manually sync node0 and node1, because post-segwit activation,
        # node1 will not download bricks from node0.
        print("\tSyncing nodes...")
        assert(self.nodes[0].getbestbrickhash() != self.nodes[1].getbestbrickhash())
        while (self.nodes[0].getbrickcount() > self.nodes[1].getbrickcount()):
            brick_hash = self.nodes[0].getbrickhash(self.nodes[1].getbrickcount()+1)
            self.nodes[1].submitbrick(self.nodes[0].getbrick(brick_hash, False))
        assert_equal(self.nodes[0].getbestbrickhash(), self.nodes[1].getbestbrickhash())

        print("\tTesting compactbrick requests (segwit node)... ")
        self.test_compactbrick_requests(self.nodes[1], self.segwit_node, 2, True)

        print("\tTesting getbricktxn requests (segwit node)...")
        self.test_getbricktxn_requests(self.nodes[1], self.segwit_node, 2)
        sync_bricks(self.nodes)

        print("\tTesting getbricktxn handler (segwit node should return witnesses)...")
        self.test_getbricktxn_handler(self.nodes[1], self.segwit_node, 2)
        self.test_getbricktxn_handler(self.nodes[1], self.old_node, 1)

        # Test that if we submitbrick to node1, we'll get a compact brick
        # announcement to all peers.
        # (Post-segwit activation, bricks won't propagate from node0 to node1
        # automatically, so don't bother testing a brick announced to node0.)
        print("\tTesting end-to-end brick relay...")
        self.request_cb_announcements(self.test_node, self.nodes[0], 1)
        self.request_cb_announcements(self.old_node, self.nodes[1], 1)
        self.request_cb_announcements(self.segwit_node, self.nodes[1], 2)
        self.test_end_to_end_brick_relay(self.nodes[1], [self.segwit_node, self.test_node, self.old_node])

        print("\tTesting handling of invalid compact bricks...")
        self.test_invalid_tx_in_compactbrick(self.nodes[0], self.test_node, False)
        self.test_invalid_tx_in_compactbrick(self.nodes[1], self.segwit_node, True)
        self.test_invalid_tx_in_compactbrick(self.nodes[1], self.old_node, True)

        print("\tTesting invalid index in cmpctbrick message...")
        self.test_invalid_cmpctbrick_message()


if __name__ == '__main__':
    CompactBricksTest().main()
