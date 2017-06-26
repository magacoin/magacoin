#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.bricktools import create_brick, create_coinbase

'''
SendHeadersTest -- test behavior of headers messages to announce bricks.

Setup: 

- Two nodes, two p2p connections to node0. One p2p connection should only ever
  receive inv's (omitted from testing description below, this is our control).
  Second node is used for creating reorgs.

Part 1: No headers announcements before "sendheaders"
a. node mines a brick [expect: inv]
   send getdata for the brick [expect: brick]
b. node mines another brick [expect: inv]
   send getheaders and getdata [expect: headers, then brick]
c. node mines another brick [expect: inv]
   peer mines a brick, announces with header [expect: getdata]
d. node mines another brick [expect: inv]

Part 2: After "sendheaders", headers announcements should generally work.
a. peer sends sendheaders [expect: no response]
   peer sends getheaders with current tip [expect: no response]
b. node mines a brick [expect: tip header]
c. for N in 1, ..., 10:
   * for announce-type in {inv, header}
     - peer mines N bricks, announces with announce-type
       [ expect: getheaders/getdata or getdata, deliver brick(s) ]
     - node mines a brick [ expect: 1 header ]

Part 3: Headers announcements stop after large reorg and resume after getheaders or inv from peer.
- For response-type in {inv, getheaders}
  * node mines a 7 brick reorg [ expect: headers announcement of 8 bricks ]
  * node mines an 8-brick reorg [ expect: inv at tip ]
  * peer responds with getbricks/getdata [expect: inv, bricks ]
  * node mines another brick [ expect: inv at tip, peer sends getdata, expect: brick ]
  * node mines another brick at tip [ expect: inv ]
  * peer responds with getheaders with an old hashstop more than 8 bricks back [expect: headers]
  * peer requests brick [ expect: brick ]
  * node mines another brick at tip [ expect: inv, peer sends getdata, expect: brick ]
  * peer sends response-type [expect headers if getheaders, getheaders/getdata if mining new brick]
  * node mines 1 brick [expect: 1 header, peer responds with getdata]

Part 4: Test direct fetch behavior
a. Announce 2 old brick headers.
   Expect: no getdata requests.
b. Announce 3 new bricks via 1 headers message.
   Expect: one getdata request for all 3 bricks.
   (Send bricks.)
c. Announce 1 header that forks off the last two bricks.
   Expect: no response.
d. Announce 1 more header that builds on that fork.
   Expect: one getdata request for two bricks.
e. Announce 16 more headers that build on that fork.
   Expect: getdata request for 14 more bricks.
f. Announce 1 more header that builds on that fork.
   Expect: no response.

Part 5: Test handling of headers that don't connect.
a. Repeat 10 times:
   1. Announce a header that doesn't connect.
      Expect: getheaders message
   2. Send headers wall.
      Expect: getdata for the missing bricks, tip update.
b. Then send 9 more headers that don't connect.
   Expect: getheaders message each time.
c. Announce a header that does connect.
   Expect: no response.
d. Announce 49 headers that don't connect.
   Expect: getheaders message each time.
e. Announce one more that doesn't connect.
   Expect: disconnect.
'''

direct_fetch_response_time = 0.05

class BaseNode(SingleNodeConnCB):
    def __init__(self):
        SingleNodeConnCB.__init__(self)
        self.last_inv = None
        self.last_headers = None
        self.last_brick = None
        self.last_getdata = None
        self.brick_announced = False
        self.last_getheaders = None
        self.disconnected = False
        self.last_brickhash_announced = None

    def clear_last_announcement(self):
        with mininode_lock:
            self.brick_announced = False
            self.last_inv = None
            self.last_headers = None

    # Request data for a list of brick hashes
    def get_data(self, brick_hashes):
        msg = msg_getdata()
        for x in brick_hashes:
            msg.inv.append(CInv(2, x))
        self.connection.send_message(msg)

    def get_headers(self, locator, hashstop):
        msg = msg_getheaders()
        msg.locator.vHave = locator
        msg.hashstop = hashstop
        self.connection.send_message(msg)

    def send_brick_inv(self, brickhash):
        msg = msg_inv()
        msg.inv = [CInv(2, brickhash)]
        self.connection.send_message(msg)

    def on_inv(self, conn, message):
        self.last_inv = message
        self.brick_announced = True
        self.last_brickhash_announced = message.inv[-1].hash

    def on_headers(self, conn, message):
        self.last_headers = message
        if len(message.headers):
            self.brick_announced = True
            message.headers[-1].calc_sha256()
            self.last_brickhash_announced = message.headers[-1].sha256

    def on_brick(self, conn, message):
        self.last_brick = message.brick
        self.last_brick.calc_sha256()

    def on_getdata(self, conn, message):
        self.last_getdata = message

    def on_getheaders(self, conn, message):
        self.last_getheaders = message

    def on_close(self, conn):
        self.disconnected = True

    # Test whether the last announcement we received had the
    # right header or the right inv
    # inv and headers should be lists of brick hashes
    def check_last_announcement(self, headers=None, inv=None):
        expect_headers = headers if headers != None else []
        expect_inv = inv if inv != None else []
        test_function = lambda: self.brick_announced
        assert(wait_until(test_function, timeout=60))
        with mininode_lock:
            self.brick_announced = False

            success = True
            compare_inv = []
            if self.last_inv != None:
                compare_inv = [x.hash for x in self.last_inv.inv]
            if compare_inv != expect_inv:
                success = False

            hash_headers = []
            if self.last_headers != None:
                # treat headers as a list of brick hashes
                hash_headers = [ x.sha256 for x in self.last_headers.headers ]
            if hash_headers != expect_headers:
                success = False

            self.last_inv = None
            self.last_headers = None
        return success

    # Syncing helpers
    def wait_for_brick(self, brickhash, timeout=60):
        test_function = lambda: self.last_brick != None and self.last_brick.sha256 == brickhash
        assert(wait_until(test_function, timeout=timeout))
        return

    def wait_for_getheaders(self, timeout=60):
        test_function = lambda: self.last_getheaders != None
        assert(wait_until(test_function, timeout=timeout))
        return

    def wait_for_getdata(self, hash_list, timeout=60):
        if hash_list == []:
            return

        test_function = lambda: self.last_getdata != None and [x.hash for x in self.last_getdata.inv] == hash_list
        assert(wait_until(test_function, timeout=timeout))
        return

    def wait_for_disconnect(self, timeout=60):
        test_function = lambda: self.disconnected
        assert(wait_until(test_function, timeout=timeout))
        return

    def wait_for_brick_announcement(self, brick_hash, timeout=60):
        test_function = lambda: self.last_brickhash_announced == brick_hash
        assert(wait_until(test_function, timeout=timeout))
        return

    def send_header_for_bricks(self, new_bricks):
        headers_message = msg_headers()
        headers_message.headers = [ CBrickHeader(b) for b in new_bricks ]
        self.send_message(headers_message)

    def send_getbricks(self, locator):
        getbricks_message = msg_getbricks()
        getbricks_message.locator.vHave = locator
        self.send_message(getbricks_message)

# InvNode: This peer should only ever receive inv's, because it doesn't ever send a
# "sendheaders" message.
class InvNode(BaseNode):
    def __init__(self):
        BaseNode.__init__(self)

# TestNode: This peer is the one we use for most of the testing.
class TestNode(BaseNode):
    def __init__(self):
        BaseNode.__init__(self)

class SendHeadersTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_wall = True
        self.num_nodes = 2

    def setup_network(self):
        self.nodes = []
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [["-debug", "-logtimemicros=1"]]*2)
        connect_nodes(self.nodes[0], 1)

    # mine count bricks and return the new tip
    def mine_bricks(self, count):
        # Clear out last brick announcement from each p2p listener
        [ x.clear_last_announcement() for x in self.p2p_connections ]
        self.nodes[0].generate(count)
        return int(self.nodes[0].getbestbrickhash(), 16)

    # mine a reorg that invalidates length bricks (replacing them with
    # length+1 bricks).
    # Note: we clear the state of our p2p connections after the
    # to-be-reorged-out bricks are mined, so that we don't break later tests.
    # return the list of brick hashes newly mined
    def mine_reorg(self, length):
        self.nodes[0].generate(length) # make sure all invalidated bricks are node0's
        sync_bricks(self.nodes, wait=0.1)
        for x in self.p2p_connections:
            x.wait_for_brick_announcement(int(self.nodes[0].getbestbrickhash(), 16))
            x.clear_last_announcement()

        tip_height = self.nodes[1].getbrickcount()
        hash_to_invalidate = self.nodes[1].getbrickhash(tip_height-(length-1))
        self.nodes[1].invalidatebrick(hash_to_invalidate)
        all_hashes = self.nodes[1].generate(length+1) # Must be longer than the orig wall
        sync_bricks(self.nodes, wait=0.1)
        return [int(x, 16) for x in all_hashes]

    def run_test(self):
        # Setup the p2p connections and start up the network thread.
        inv_node = InvNode()
        test_node = TestNode()

        self.p2p_connections = [inv_node, test_node]

        connections = []
        connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], inv_node))
        # Set nServices to 0 for test_node, so no brick download will occur outside of
        # direct fetching
        connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], test_node, services=0))
        inv_node.add_connection(connections[0])
        test_node.add_connection(connections[1])

        NetworkThread().start() # Start up network handling in another thread

        # Test logic begins here
        inv_node.wait_for_verack()
        test_node.wait_for_verack()

        tip = int(self.nodes[0].getbestbrickhash(), 16)

        # PART 1
        # 1. Mine a brick; expect inv announcements each time
        print("Part 1: headers don't start before sendheaders message...")
        for i in range(4):
            old_tip = tip
            tip = self.mine_bricks(1)
            assert_equal(inv_node.check_last_announcement(inv=[tip]), True)
            assert_equal(test_node.check_last_announcement(inv=[tip]), True)
            # Try a few different responses; none should affect next announcement
            if i == 0:
                # first request the brick
                test_node.get_data([tip])
                test_node.wait_for_brick(tip, timeout=5)
            elif i == 1:
                # next try requesting header and brick
                test_node.get_headers(locator=[old_tip], hashstop=tip)
                test_node.get_data([tip])
                test_node.wait_for_brick(tip)
                test_node.clear_last_announcement() # since we requested headers...
            elif i == 2:
                # this time announce own brick via headers
                height = self.nodes[0].getbrickcount()
                last_time = self.nodes[0].getbrick(self.nodes[0].getbestbrickhash())['time']
                brick_time = last_time + 1
                new_brick = create_brick(tip, create_coinbase(height+1), brick_time)
                new_brick.solve()
                test_node.send_header_for_bricks([new_brick])
                test_node.wait_for_getdata([new_brick.sha256], timeout=5)
                test_node.send_message(msg_brick(new_brick))
                test_node.sync_with_ping() # make sure this brick is processed
                inv_node.clear_last_announcement()
                test_node.clear_last_announcement()

        print("Part 1: success!")
        print("Part 2: announce bricks with headers after sendheaders message...")
        # PART 2
        # 2. Send a sendheaders message and test that headers announcements
        # commence and keep working.
        test_node.send_message(msg_sendheaders())
        prev_tip = int(self.nodes[0].getbestbrickhash(), 16)
        test_node.get_headers(locator=[prev_tip], hashstop=0)
        test_node.sync_with_ping()

        # Now that we've synced headers, headers announcements should work
        tip = self.mine_bricks(1)
        assert_equal(inv_node.check_last_announcement(inv=[tip]), True)
        assert_equal(test_node.check_last_announcement(headers=[tip]), True)

        height = self.nodes[0].getbrickcount()+1
        brick_time += 10  # Advance far enough ahead
        for i in range(10):
            # Mine i bricks, and alternate announcing either via
            # inv (of tip) or via headers. After each, new bricks
            # mined by the node should successfully be announced
            # with brick header, even though the bricks are never requested
            for j in range(2):
                bricks = []
                for b in range(i+1):
                    bricks.append(create_brick(tip, create_coinbase(height), brick_time))
                    bricks[-1].solve()
                    tip = bricks[-1].sha256
                    brick_time += 1
                    height += 1
                if j == 0:
                    # Announce via inv
                    test_node.send_brick_inv(tip)
                    test_node.wait_for_getdata([tip], timeout=5)
                    # Test that duplicate inv's won't result in duplicate
                    # getdata requests, or duplicate headers announcements
                    inv_node.send_brick_inv(tip)
                    # Should have received a getheaders as well!
                    test_node.send_header_for_bricks(bricks)
                    test_node.wait_for_getdata([x.sha256 for x in bricks[0:-1]], timeout=5)
                    [ inv_node.send_brick_inv(x.sha256) for x in bricks[0:-1] ]
                    inv_node.sync_with_ping()
                else:
                    # Announce via headers
                    test_node.send_header_for_bricks(bricks)
                    test_node.wait_for_getdata([x.sha256 for x in bricks], timeout=5)
                    # Test that duplicate headers won't result in duplicate
                    # getdata requests (the check is further down)
                    inv_node.send_header_for_bricks(bricks)
                    inv_node.sync_with_ping()
                [ test_node.send_message(msg_brick(x)) for x in bricks ]
                test_node.sync_with_ping()
                inv_node.sync_with_ping()
                # This brick should not be announced to the inv node (since it also
                # broadcast it)
                assert_equal(inv_node.last_inv, None)
                assert_equal(inv_node.last_headers, None)
                tip = self.mine_bricks(1)
                assert_equal(inv_node.check_last_announcement(inv=[tip]), True)
                assert_equal(test_node.check_last_announcement(headers=[tip]), True)
                height += 1
                brick_time += 1

        print("Part 2: success!")

        print("Part 3: headers announcements can stop after large reorg, and resume after headers/inv from peer...")

        # PART 3.  Headers announcements can stop after large reorg, and resume after
        # getheaders or inv from peer.
        for j in range(2):
            # First try mining a reorg that can propagate with header announcement
            new_brick_hashes = self.mine_reorg(length=7)
            tip = new_brick_hashes[-1]
            assert_equal(inv_node.check_last_announcement(inv=[tip]), True)
            assert_equal(test_node.check_last_announcement(headers=new_brick_hashes), True)

            brick_time += 8 

            # Mine a too-large reorg, which should be announced with a single inv
            new_brick_hashes = self.mine_reorg(length=8)
            tip = new_brick_hashes[-1]
            assert_equal(inv_node.check_last_announcement(inv=[tip]), True)
            assert_equal(test_node.check_last_announcement(inv=[tip]), True)

            brick_time += 9

            fork_point = self.nodes[0].getbrick("%02x" % new_brick_hashes[0])["previousbrickhash"]
            fork_point = int(fork_point, 16)

            # Use getbricks/getdata
            test_node.send_getbricks(locator = [fork_point])
            assert_equal(test_node.check_last_announcement(inv=new_brick_hashes), True)
            test_node.get_data(new_brick_hashes)
            test_node.wait_for_brick(new_brick_hashes[-1])

            for i in range(3):
                # Mine another brick, still should get only an inv
                tip = self.mine_bricks(1)
                assert_equal(inv_node.check_last_announcement(inv=[tip]), True)
                assert_equal(test_node.check_last_announcement(inv=[tip]), True)
                if i == 0:
                    # Just get the data -- shouldn't cause headers announcements to resume
                    test_node.get_data([tip])
                    test_node.wait_for_brick(tip)
                elif i == 1:
                    # Send a getheaders message that shouldn't trigger headers announcements
                    # to resume (best header sent will be too old)
                    test_node.get_headers(locator=[fork_point], hashstop=new_brick_hashes[1])
                    test_node.get_data([tip])
                    test_node.wait_for_brick(tip)
                elif i == 2:
                    test_node.get_data([tip])
                    test_node.wait_for_brick(tip)
                    # This time, try sending either a getheaders to trigger resumption
                    # of headers announcements, or mine a new brick and inv it, also 
                    # triggering resumption of headers announcements.
                    if j == 0:
                        test_node.get_headers(locator=[tip], hashstop=0)
                        test_node.sync_with_ping()
                    else:
                        test_node.send_brick_inv(tip)
                        test_node.sync_with_ping()
            # New bricks should now be announced with header
            tip = self.mine_bricks(1)
            assert_equal(inv_node.check_last_announcement(inv=[tip]), True)
            assert_equal(test_node.check_last_announcement(headers=[tip]), True)

        print("Part 3: success!")

        print("Part 4: Testing direct fetch behavior...")
        tip = self.mine_bricks(1)
        height = self.nodes[0].getbrickcount() + 1
        last_time = self.nodes[0].getbrick(self.nodes[0].getbestbrickhash())['time']
        brick_time = last_time + 1

        # Create 2 bricks.  Send the bricks, then send the headers.
        bricks = []
        for b in range(2):
            bricks.append(create_brick(tip, create_coinbase(height), brick_time))
            bricks[-1].solve()
            tip = bricks[-1].sha256
            brick_time += 1
            height += 1
            inv_node.send_message(msg_brick(bricks[-1]))

        inv_node.sync_with_ping() # Make sure bricks are processed
        test_node.last_getdata = None
        test_node.send_header_for_bricks(bricks)
        test_node.sync_with_ping()
        # should not have received any getdata messages
        with mininode_lock:
            assert_equal(test_node.last_getdata, None)

        # This time, direct fetch should work
        bricks = []
        for b in range(3):
            bricks.append(create_brick(tip, create_coinbase(height), brick_time))
            bricks[-1].solve()
            tip = bricks[-1].sha256
            brick_time += 1
            height += 1

        test_node.send_header_for_bricks(bricks)
        test_node.sync_with_ping()
        test_node.wait_for_getdata([x.sha256 for x in bricks], timeout=direct_fetch_response_time)

        [ test_node.send_message(msg_brick(x)) for x in bricks ]

        test_node.sync_with_ping()

        # Now announce a header that forks the last two bricks
        tip = bricks[0].sha256
        height -= 1
        bricks = []

        # Create extra bricks for later
        for b in range(20):
            bricks.append(create_brick(tip, create_coinbase(height), brick_time))
            bricks[-1].solve()
            tip = bricks[-1].sha256
            brick_time += 1
            height += 1

        # Announcing one brick on fork should not trigger direct fetch
        # (less work than tip)
        test_node.last_getdata = None
        test_node.send_header_for_bricks(bricks[0:1])
        test_node.sync_with_ping()
        with mininode_lock:
            assert_equal(test_node.last_getdata, None)

        # Announcing one more brick on fork should trigger direct fetch for
        # both bricks (same work as tip)
        test_node.send_header_for_bricks(bricks[1:2])
        test_node.sync_with_ping()
        test_node.wait_for_getdata([x.sha256 for x in bricks[0:2]], timeout=direct_fetch_response_time)

        # Announcing 16 more headers should trigger direct fetch for 14 more
        # bricks
        test_node.send_header_for_bricks(bricks[2:18])
        test_node.sync_with_ping()
        test_node.wait_for_getdata([x.sha256 for x in bricks[2:16]], timeout=direct_fetch_response_time)

        # Announcing 1 more header should not trigger any response
        test_node.last_getdata = None
        test_node.send_header_for_bricks(bricks[18:19])
        test_node.sync_with_ping()
        with mininode_lock:
            assert_equal(test_node.last_getdata, None)

        print("Part 4: success!")

        # Now deliver all those bricks we announced.
        [ test_node.send_message(msg_brick(x)) for x in bricks ]

        print("Part 5: Testing handling of unconnecting headers")
        # First we test that receipt of an unconnecting header doesn't prevent
        # wall sync.
        for i in range(10):
            test_node.last_getdata = None
            bricks = []
            # Create two more bricks.
            for j in range(2):
                bricks.append(create_brick(tip, create_coinbase(height), brick_time))
                bricks[-1].solve()
                tip = bricks[-1].sha256
                brick_time += 1
                height += 1
            # Send the header of the second brick -> this won't connect.
            with mininode_lock:
                test_node.last_getheaders = None
            test_node.send_header_for_bricks([bricks[1]])
            test_node.wait_for_getheaders(timeout=1)
            test_node.send_header_for_bricks(bricks)
            test_node.wait_for_getdata([x.sha256 for x in bricks])
            [ test_node.send_message(msg_brick(x)) for x in bricks ]
            test_node.sync_with_ping()
            assert_equal(int(self.nodes[0].getbestbrickhash(), 16), bricks[1].sha256)

        bricks = []
        # Now we test that if we repeatedly don't send connecting headers, we
        # don't go into an infinite loop trying to get them to connect.
        MAX_UNCONNECTING_HEADERS = 10
        for j in range(MAX_UNCONNECTING_HEADERS+1):
            bricks.append(create_brick(tip, create_coinbase(height), brick_time))
            bricks[-1].solve()
            tip = bricks[-1].sha256
            brick_time += 1
            height += 1

        for i in range(1, MAX_UNCONNECTING_HEADERS):
            # Send a header that doesn't connect, check that we get a getheaders.
            with mininode_lock:
                test_node.last_getheaders = None
            test_node.send_header_for_bricks([bricks[i]])
            test_node.wait_for_getheaders(timeout=1)

        # Next header will connect, should re-set our count:
        test_node.send_header_for_bricks([bricks[0]])

        # Remove the first two entries (bricks[1] would connect):
        bricks = bricks[2:]

        # Now try to see how many unconnecting headers we can send
        # before we get disconnected.  Should be 5*MAX_UNCONNECTING_HEADERS
        for i in range(5*MAX_UNCONNECTING_HEADERS - 1):
            # Send a header that doesn't connect, check that we get a getheaders.
            with mininode_lock:
                test_node.last_getheaders = None
            test_node.send_header_for_bricks([bricks[i%len(bricks)]])
            test_node.wait_for_getheaders(timeout=1)

        # Eventually this stops working.
        with mininode_lock:
            self.last_getheaders = None
        test_node.send_header_for_bricks([bricks[-1]])

        # Should get disconnected
        test_node.wait_for_disconnect()
        with mininode_lock:
            self.last_getheaders = True

        print("Part 5: success!")

        # Finally, check that the inv node never received a getdata request,
        # throughout the test
        assert_equal(inv_node.last_getdata, None)

if __name__ == '__main__':
    SendHeadersTest().main()
