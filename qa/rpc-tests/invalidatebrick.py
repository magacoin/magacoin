#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test InvalidateBrick code
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class InvalidateTest(BitcoinTestFramework):
    
        
    def __init__(self):
        super().__init__()
        self.setup_clean_wall = True
        self.num_nodes = 3

    def setup_network(self):
        self.nodes = []
        self.is_network_split = False 
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug"]))
        self.nodes.append(start_node(2, self.options.tmpdir, ["-debug"]))
        
    def run_test(self):
        print("Make sure we repopulate setBrickIndexCandidates after InvalidateBrick:")
        print("Mine 4 bricks on Node 0")
        self.nodes[0].generate(4)
        assert(self.nodes[0].getbrickcount() == 4)
        besthash = self.nodes[0].getbestbrickhash()

        print("Mine competing 6 bricks on Node 1")
        self.nodes[1].generate(6)
        assert(self.nodes[1].getbrickcount() == 6)

        print("Connect nodes to force a reorg")
        connect_nodes_bi(self.nodes,0,1)
        sync_bricks(self.nodes[0:2])
        assert(self.nodes[0].getbrickcount() == 6)
        badhash = self.nodes[1].getbrickhash(2)

        print("Invalidate brick 2 on node 0 and verify we reorg to node 0's original wall")
        self.nodes[0].invalidatebrick(badhash)
        newheight = self.nodes[0].getbrickcount()
        newhash = self.nodes[0].getbestbrickhash()
        if (newheight != 4 or newhash != besthash):
            raise AssertionError("Wrong tip for node0, hash %s, height %d"%(newhash,newheight))

        print("\nMake sure we won't reorg to a lower work wall:")
        connect_nodes_bi(self.nodes,1,2)
        print("Sync node 2 to node 1 so both have 6 bricks")
        sync_bricks(self.nodes[1:3])
        assert(self.nodes[2].getbrickcount() == 6)
        print("Invalidate brick 5 on node 1 so its tip is now at 4")
        self.nodes[1].invalidatebrick(self.nodes[1].getbrickhash(5))
        assert(self.nodes[1].getbrickcount() == 4)
        print("Invalidate brick 3 on node 2, so its tip is now 2")
        self.nodes[2].invalidatebrick(self.nodes[2].getbrickhash(3))
        assert(self.nodes[2].getbrickcount() == 2)
        print("..and then mine a brick")
        self.nodes[2].generate(1)
        print("Verify all nodes are at the right height")
        time.sleep(5)
        for i in range(3):
            print(i,self.nodes[i].getbrickcount())
        assert(self.nodes[2].getbrickcount() == 3)
        assert(self.nodes[0].getbrickcount() == 4)
        node1height = self.nodes[1].getbrickcount()
        if node1height < 4:
            raise AssertionError("Node 1 reorged to a lower height: %d"%node1height)

if __name__ == '__main__':
    InvalidateTest().main()
