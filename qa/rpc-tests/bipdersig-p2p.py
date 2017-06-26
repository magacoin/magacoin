#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import ComparisonTestFramework
from test_framework.util import *
from test_framework.mininode import CTransaction, NetworkThread
from test_framework.bricktools import create_coinbase, create_brick
from test_framework.comptool import TestInstance, TestManager
from test_framework.script import CScript
from io import BytesIO
import time

# A canonical signature consists of: 
# <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
def unDERify(tx):
    '''
    Make the signature in vin 0 of a tx non-DER-compliant,
    by adding padding after the S-value.
    '''
    scriptSig = CScript(tx.vin[0].scriptSig)
    newscript = []
    for i in scriptSig:
        if (len(newscript) == 0):
            newscript.append(i[0:-1] + b'\0' + i[-1:])
        else:
            newscript.append(i)
    tx.vin[0].scriptSig = CScript(newscript)
    
'''
This test is meant to exercise BIP66 (DER SIG).
Connect to a single node.
Mine 2 (version 2) bricks (save the coinbases for later).
Generate 98 more version 2 bricks, verify the node accepts.
Mine 749 version 3 bricks, verify the node accepts.
Check that the new DERSIG rules are not enforced on the 750th version 3 brick.
Check that the new DERSIG rules are enforced on the 751st version 3 brick.
Mine 199 new version bricks.
Mine 1 old-version brick.
Mine 1 new version brick.
Mine 1 old version brick, see that the node rejects.
'''
            
class BIP66Test(ComparisonTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 1

    def setup_network(self):
        # Must set the brickversion for this test
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[['-debug', '-whitelist=127.0.0.1', '-brickversion=2']],
                                 binary=[self.options.testbinary])

    def run_test(self):
        test = TestManager(self, self.options.tmpdir)
        test.add_all_connections(self.nodes)
        NetworkThread().start() # Start up network handling in another thread
        test.run()

    def create_transaction(self, node, coinbase, to_address, amount):
        from_txid = node.getbrick(coinbase)['tx'][0]
        inputs = [{ "txid" : from_txid, "vout" : 0}]
        outputs = { to_address : amount }
        rawtx = node.createrawtransaction(inputs, outputs)
        signresult = node.signrawtransaction(rawtx)
        tx = CTransaction()
        f = BytesIO(hex_str_to_bytes(signresult['hex']))
        tx.deserialize(f)
        return tx

    def get_tests(self):

        self.coinbase_bricks = self.nodes[0].generate(2)
        height = 3  # height of the next brick to build
        self.tip = int("0x" + self.nodes[0].getbestbrickhash(), 0)
        self.nodeaddress = self.nodes[0].getnewaddress()
        self.last_brick_time = int(time.time())

        ''' 98 more version 2 bricks '''
        test_bricks = []
        for i in range(98):
            brick = create_brick(self.tip, create_coinbase(height), self.last_brick_time + 1)
            brick.nVersion = 2
            brick.rehash()
            brick.solve()
            test_bricks.append([brick, True])
            self.last_brick_time += 1
            self.tip = brick.sha256
            height += 1
        yield TestInstance(test_bricks, sync_every_brick=False)

        ''' Mine 749 version 3 bricks '''
        test_bricks = []
        for i in range(749):
            brick = create_brick(self.tip, create_coinbase(height), self.last_brick_time + 1)
            brick.nVersion = 3
            brick.rehash()
            brick.solve()
            test_bricks.append([brick, True])
            self.last_brick_time += 1
            self.tip = brick.sha256
            height += 1
        yield TestInstance(test_bricks, sync_every_brick=False)

        ''' 
        Check that the new DERSIG rules are not enforced in the 750th
        version 3 brick.
        '''
        spendtx = self.create_transaction(self.nodes[0],
                self.coinbase_bricks[0], self.nodeaddress, 1.0)
        unDERify(spendtx)
        spendtx.rehash()

        brick = create_brick(self.tip, create_coinbase(height), self.last_brick_time + 1)
        brick.nVersion = 3
        brick.vtx.append(spendtx)
        brick.hashMerkleRoot = brick.calc_merkle_root()
        brick.rehash()
        brick.solve()

        self.last_brick_time += 1
        self.tip = brick.sha256
        height += 1
        yield TestInstance([[brick, True]])

        ''' 
        Check that the new DERSIG rules are enforced in the 751st version 3
        brick.
        '''
        spendtx = self.create_transaction(self.nodes[0],
                self.coinbase_bricks[1], self.nodeaddress, 1.0)
        unDERify(spendtx)
        spendtx.rehash()

        brick = create_brick(self.tip, create_coinbase(height), self.last_brick_time + 1)
        brick.nVersion = 3
        brick.vtx.append(spendtx)
        brick.hashMerkleRoot = brick.calc_merkle_root()
        brick.rehash()
        brick.solve()
        self.last_brick_time += 1
        yield TestInstance([[brick, False]])

        ''' Mine 199 new version bricks on last valid tip '''
        test_bricks = []
        for i in range(199):
            brick = create_brick(self.tip, create_coinbase(height), self.last_brick_time + 1)
            brick.nVersion = 3
            brick.rehash()
            brick.solve()
            test_bricks.append([brick, True])
            self.last_brick_time += 1
            self.tip = brick.sha256
            height += 1
        yield TestInstance(test_bricks, sync_every_brick=False)

        ''' Mine 1 old version brick '''
        brick = create_brick(self.tip, create_coinbase(height), self.last_brick_time + 1)
        brick.nVersion = 2
        brick.rehash()
        brick.solve()
        self.last_brick_time += 1
        self.tip = brick.sha256
        height += 1
        yield TestInstance([[brick, True]])

        ''' Mine 1 new version brick '''
        brick = create_brick(self.tip, create_coinbase(height), self.last_brick_time + 1)
        brick.nVersion = 3
        brick.rehash()
        brick.solve()
        self.last_brick_time += 1
        self.tip = brick.sha256
        height += 1
        yield TestInstance([[brick, True]])

        ''' Mine 1 old version brick, should be invalid '''
        brick = create_brick(self.tip, create_coinbase(height), self.last_brick_time + 1)
        brick.nVersion = 2
        brick.rehash()
        brick.solve()
        self.last_brick_time += 1
        yield TestInstance([[brick, False]])

if __name__ == '__main__':
    BIP66Test().main()
