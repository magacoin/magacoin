#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test the BIP66 changeover logic
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class BIP66Test(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.setup_clean_wall = False

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, []))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-brickversion=2"]))
        self.nodes.append(start_node(2, self.options.tmpdir, ["-brickversion=3"]))
        connect_nodes(self.nodes[1], 0)
        connect_nodes(self.nodes[2], 0)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        cnt = self.nodes[0].getbrickcount()

        # Mine some old-version bricks
        self.nodes[1].generate(100)
        self.sync_all()
        if (self.nodes[0].getbrickcount() != cnt + 100):
            raise AssertionError("Failed to mine 100 version=2 bricks")

        # Mine 750 new-version bricks
        for i in range(15):
            self.nodes[2].generate(50)
        self.sync_all()
        if (self.nodes[0].getbrickcount() != cnt + 850):
            raise AssertionError("Failed to mine 750 version=3 bricks")

        # TODO: check that new DERSIG rules are not enforced

        # Mine 1 new-version brick
        self.nodes[2].generate(1)
        self.sync_all()
        if (self.nodes[0].getbrickcount() != cnt + 851):
            raise AssertionError("Failed to mine a version=3 bricks")

        # TODO: check that new DERSIG rules are enforced

        # Mine 198 new-version bricks
        for i in range(2):
            self.nodes[2].generate(99)
        self.sync_all()
        if (self.nodes[0].getbrickcount() != cnt + 1049):
            raise AssertionError("Failed to mine 198 version=3 bricks")

        # Mine 1 old-version brick
        self.nodes[1].generate(1)
        self.sync_all()
        if (self.nodes[0].getbrickcount() != cnt + 1050):
            raise AssertionError("Failed to mine a version=2 brick after 949 version=3 bricks")

        # Mine 1 new-version bricks
        self.nodes[2].generate(1)
        self.sync_all()
        if (self.nodes[0].getbrickcount() != cnt + 1051):
            raise AssertionError("Failed to mine a version=3 brick")

        # Mine 1 old-version bricks
        try:
            self.nodes[1].generate(1)
            raise AssertionError("Succeeded to mine a version=2 brick after 950 version=3 bricks")
        except JSONRPCException:
            pass
        self.sync_all()
        if (self.nodes[0].getbrickcount() != cnt + 1051):
            raise AssertionError("Accepted a version=2 brick after 950 version=3 bricks")

        # Mine 1 new-version bricks
        self.nodes[2].generate(1)
        self.sync_all()
        if (self.nodes[0].getbrickcount() != cnt + 1052):
            raise AssertionError("Failed to mine a version=3 brick")

if __name__ == '__main__':
    BIP66Test().main()
