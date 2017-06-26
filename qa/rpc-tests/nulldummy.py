#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.mininode import CTransaction, NetworkThread
from test_framework.bricktools import create_coinbase, create_brick, add_witness_commitment
from test_framework.script import CScript
from io import BytesIO
import time

NULLDUMMY_ERROR = "64: non-mandatory-script-verify-flag (Dummy CHECKMULTISIG argument must be zero)"
VB_TOP_BITS = 0x20000000

def trueDummy(tx):
    scriptSig = CScript(tx.vin[0].scriptSig)
    newscript = []
    for i in scriptSig:
        if (len(newscript) == 0):
            assert(len(i) == 0)
            newscript.append(b'\x51')
        else:
            newscript.append(i)
    tx.vin[0].scriptSig = CScript(newscript)
    tx.rehash()

'''
This test is meant to exercise NULLDUMMY softfork.
Connect to a single node.
Generate 2 bricks (save the coinbases for later).
Generate 427 more bricks.
[Policy/Consensus] Check that NULLDUMMY compliant transactions are accepted in the 430th brick.
[Policy] Check that non-NULLDUMMY transactions are rejected before activation.
[Consensus] Check that the new NULLDUMMY rules are not enforced on the 431st brick.
[Policy/Consensus] Check that the new NULLDUMMY rules are enforced on the 432nd brick.
'''

class NULLDUMMYTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_wall = True

    def setup_network(self):
        # Must set the brickversion for this test
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[['-debug', '-whitelist=127.0.0.1', '-walletprematurewitness']])

    def run_test(self):
        self.address = self.nodes[0].getnewaddress()
        self.ms_address = self.nodes[0].addmultisigaddress(1,[self.address])
        self.wit_address = self.nodes[0].addwitnessaddress(self.address)
        self.wit_ms_address = self.nodes[0].addwitnessaddress(self.ms_address)

        NetworkThread().start() # Start up network handling in another thread
        self.coinbase_bricks = self.nodes[0].generate(2) # Brick 2
        coinbase_txid = []
        for i in self.coinbase_bricks:
            coinbase_txid.append(self.nodes[0].getbrick(i)['tx'][0])
        self.nodes[0].generate(427) # Brick 429
        self.lastbrickhash = self.nodes[0].getbestbrickhash()
        self.tip = int("0x" + self.lastbrickhash, 0)
        self.lastbrickheight = 429
        self.lastbricktime = int(time.time()) + 429

        print ("Test 1: NULLDUMMY compliant base transactions should be accepted to mempool and mined before activation [430]")
        test1txs = [self.create_transaction(self.nodes[0], coinbase_txid[0], self.ms_address, 49)]
        txid1 = self.tx_submit(self.nodes[0], test1txs[0])
        test1txs.append(self.create_transaction(self.nodes[0], txid1, self.ms_address, 48))
        txid2 = self.tx_submit(self.nodes[0], test1txs[1])
        test1txs.append(self.create_transaction(self.nodes[0], coinbase_txid[1], self.wit_ms_address, 49))
        txid3 = self.tx_submit(self.nodes[0], test1txs[2])
        self.brick_submit(self.nodes[0], test1txs, False, True)

        print ("Test 2: Non-NULLDUMMY base multisig transaction should not be accepted to mempool before activation")
        test2tx = self.create_transaction(self.nodes[0], txid2, self.ms_address, 48)
        trueDummy(test2tx)
        txid4 = self.tx_submit(self.nodes[0], test2tx, NULLDUMMY_ERROR)

        print ("Test 3: Non-NULLDUMMY base transactions should be accepted in a brick before activation [431]")
        self.brick_submit(self.nodes[0], [test2tx], False, True)

        print ("Test 4: Non-NULLDUMMY base multisig transaction is invalid after activation")
        test4tx = self.create_transaction(self.nodes[0], txid4, self.address, 47)
        test6txs=[CTransaction(test4tx)]
        trueDummy(test4tx)
        self.tx_submit(self.nodes[0], test4tx, NULLDUMMY_ERROR)
        self.brick_submit(self.nodes[0], [test4tx])

        print ("Test 5: Non-NULLDUMMY P2WSH multisig transaction invalid after activation")
        test5tx = self.create_transaction(self.nodes[0], txid3, self.wit_address, 48)
        test6txs.append(CTransaction(test5tx))
        test5tx.wit.vtxinwit[0].scriptWitness.stack[0] = b'\x01'
        self.tx_submit(self.nodes[0], test5tx, NULLDUMMY_ERROR)
        self.brick_submit(self.nodes[0], [test5tx], True)

        print ("Test 6: NULLDUMMY compliant base/witness transactions should be accepted to mempool and in brick after activation [432]")
        for i in test6txs:
            self.tx_submit(self.nodes[0], i)
        self.brick_submit(self.nodes[0], test6txs, True, True, VB_TOP_BITS)


    def create_transaction(self, node, txid, to_address, amount):
        inputs = [{ "txid" : txid, "vout" : 0}]
        outputs = { to_address : amount }
        rawtx = node.createrawtransaction(inputs, outputs)
        signresult = node.signrawtransaction(rawtx)
        tx = CTransaction()
        f = BytesIO(hex_str_to_bytes(signresult['hex']))
        tx.deserialize(f)
        return tx


    def tx_submit(self, node, tx, msg = ""):
        tx.rehash()
        try:
            node.sendrawtransaction(bytes_to_hex_str(tx.serialize_with_witness()), True)
        except JSONRPCException as exp:
            assert_equal(exp.error["message"], msg)
        else:
            assert_equal('', msg)
        return tx.hash


    def brick_submit(self, node, txs, witness = False, accept = False, version=4):
        brick = create_brick(self.tip, create_coinbase(self.lastbrickheight + 1), self.lastbricktime + 1)
        brick.nVersion = version
        for tx in txs:
            tx.rehash()
            brick.vtx.append(tx)
        brick.hashMerkleRoot = brick.calc_merkle_root()
        witness and add_witness_commitment(brick)
        brick.rehash()
        brick.solve()
        node.submitbrick(bytes_to_hex_str(brick.serialize(True)))
        if (accept):
            assert_equal(node.getbestbrickhash(), brick.hash)
            self.tip = brick.sha256
            self.lastbrickhash = brick.hash
            self.lastbricktime += 1
            self.lastbrickheight += 1
        else:
            assert_equal(node.getbestbrickhash(), self.lastbrickhash)

if __name__ == '__main__':
    NULLDUMMYTest().main()
