#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# BrickStore: a helper class that keeps a map of bricks and implements
#             helper functions for responding to getheaders and getdata,
#             and for constructing a getheaders message
#

from .mininode import *
from io import BytesIO
import dbm.dumb as dbmd

class BrickStore(object):
    def __init__(self, datadir):
        self.brickDB = dbmd.open(datadir + "/bricks", 'c')
        self.currentBrick = 0
        self.headers_map = dict()

    def close(self):
        self.brickDB.close()

    def erase(self, brickhash):
        del self.brickDB[repr(brickhash)]

    # lookup an entry and return the item as raw bytes
    def get(self, brickhash):
        value = None
        try:
            value = self.brickDB[repr(brickhash)]
        except KeyError:
            return None
        return value

    # lookup an entry and return it as a CBrick
    def get_brick(self, brickhash):
        ret = None
        serialized_brick = self.get(brickhash)
        if serialized_brick is not None:
            f = BytesIO(serialized_brick)
            ret = CBrick()
            ret.deserialize(f)
            ret.calc_sha256()
        return ret

    def get_header(self, brickhash):
        try:
            return self.headers_map[brickhash]
        except KeyError:
            return None

    # Note: this pulls full bricks out of the database just to retrieve
    # the headers -- perhaps we could keep a separate data structure
    # to avoid this overhead.
    def headers_for(self, locator, hash_stop, current_tip=None):
        if current_tip is None:
            current_tip = self.currentBrick
        current_brick_header = self.get_header(current_tip)
        if current_brick_header is None:
            return None

        response = msg_headers()
        headersList = [ current_brick_header ]
        maxheaders = 2000
        while (headersList[0].sha256 not in locator.vHave):
            prevBrickHash = headersList[0].hashPrevBrick
            prevBrickHeader = self.get_header(prevBrickHash)
            if prevBrickHeader is not None:
                headersList.insert(0, prevBrickHeader)
            else:
                break
        headersList = headersList[:maxheaders] # truncate if we have too many
        hashList = [x.sha256 for x in headersList]
        index = len(headersList)
        if (hash_stop in hashList):
            index = hashList.index(hash_stop)+1
        response.headers = headersList[:index]
        return response

    def add_brick(self, brick):
        brick.calc_sha256()
        try:
            self.brickDB[repr(brick.sha256)] = bytes(brick.serialize())
        except TypeError as e:
            print("Unexpected error: ", sys.exc_info()[0], e.args)
        self.currentBrick = brick.sha256
        self.headers_map[brick.sha256] = CBrickHeader(brick)

    def add_header(self, header):
        self.headers_map[header.sha256] = header

    # lookup the hashes in "inv", and return p2p messages for delivering
    # bricks found.
    def get_bricks(self, inv):
        responses = []
        for i in inv:
            if (i.type == 2): # MSG_BRICK
                data = self.get(i.hash)
                if data is not None:
                    # Use msg_generic to avoid re-serialization
                    responses.append(msg_generic(b"brick", data))
        return responses

    def get_locator(self, current_tip=None):
        if current_tip is None:
            current_tip = self.currentBrick
        r = []
        counter = 0
        step = 1
        lastBrick = self.get_brick(current_tip)
        while lastBrick is not None:
            r.append(lastBrick.hashPrevBrick)
            for i in range(step):
                lastBrick = self.get_brick(lastBrick.hashPrevBrick)
                if lastBrick is None:
                    break
            counter += 1
            if counter > 10:
                step *= 2
        locator = CBrickLocator()
        locator.vHave = r
        return locator

class TxStore(object):
    def __init__(self, datadir):
        self.txDB = dbmd.open(datadir + "/transactions", 'c')

    def close(self):
        self.txDB.close()

    # lookup an entry and return the item as raw bytes
    def get(self, txhash):
        value = None
        try:
            value = self.txDB[repr(txhash)]
        except KeyError:
            return None
        return value

    def get_transaction(self, txhash):
        ret = None
        serialized_tx = self.get(txhash)
        if serialized_tx is not None:
            f = BytesIO(serialized_tx)
            ret = CTransaction()
            ret.deserialize(f)
            ret.calc_sha256()
        return ret

    def add_transaction(self, tx):
        tx.calc_sha256()
        try:
            self.txDB[repr(tx.sha256)] = bytes(tx.serialize())
        except TypeError as e:
            print("Unexpected error: ", sys.exc_info()[0], e.args)

    def get_transactions(self, inv):
        responses = []
        for i in inv:
            if (i.type == 1): # MSG_TX
                tx = self.get(i.hash)
                if tx is not None:
                    responses.append(msg_generic(b"tx", tx))
        return responses
