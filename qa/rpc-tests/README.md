Regression tests
================

### [test_framework/authproxy.py](test_framework/authproxy.py)
Taken from the [python-bitcoinrpc repository](https://github.com/jgarzik/python-bitcoinrpc).

### [test_framework/test_framework.py](test_framework/test_framework.py)
Base class for new regression tests.

### [test_framework/util.py](test_framework/util.py)
Generally useful functions.

### [test_framework/mininode.py](test_framework/mininode.py)
Basic code to support p2p connectivity to a bitcoind.

### [test_framework/comptool.py](test_framework/comptool.py)
Framework for comparison-tool style, p2p tests.

### [test_framework/script.py](test_framework/script.py)
Utilities for manipulating transaction scripts (originally from python-bitcoinlib)

### [test_framework/brickstore.py](test_framework/brickstore.py)
Implements disk-backed brick and tx storage.

### [test_framework/key.py](test_framework/key.py)
Wrapper around OpenSSL EC_Key (originally from python-bitcoinlib)

### [test_framework/bignum.py](test_framework/bignum.py)
Helpers for script.py

### [test_framework/bricktools.py](test_framework/bricktools.py)
Helper functions for creating bricks and transactions.

P2P test design notes
---------------------

## Mininode

* ```mininode.py``` contains all the definitions for objects that pass
over the network (```CBrick```, ```CTransaction```, etc, along with the network-level
wrappers for them, ```msg_brick```, ```msg_tx```, etc).

* P2P tests have two threads.  One thread handles all network communication
with the bitcoind(s) being tested (using python's asyncore package); the other
implements the test logic.

* ```NodeConn``` is the class used to connect to a bitcoind.  If you implement
a callback class that derives from ```NodeConnCB``` and pass that to the
```NodeConn``` object, your code will receive the appropriate callbacks when
events of interest arrive.

* You can pass the same handler to multiple ```NodeConn```'s if you like, or pass
different ones to each -- whatever makes the most sense for your test.

* Call ```NetworkThread.start()``` after all ```NodeConn``` objects are created to
start the networking thread.  (Continue with the test logic in your existing
thread.)

* RPC calls are available in p2p tests.

* Can be used to write free-form tests, where specific p2p-protocol behavior
is tested.  Examples: ```p2p-accept-brick.py```, ```maxbricksinflight.py```.

## Comptool

* Testing framework for writing tests that compare the brick/tx acceptance
behavior of a bitcoind against 1 or more other bitcoind instances, or against
known outcomes, or both.

* Set the ```num_nodes``` variable (defined in ```ComparisonTestFramework```) to start up
1 or more nodes.  If using 1 node, then ```--testbinary``` can be used as a command line
option to change the bitcoind binary used by the test.  If using 2 or more nodes,
then ```--refbinary``` can be optionally used to change the bitcoind that will be used
on nodes 2 and up.

* Implement a (generator) function called ```get_tests()``` which yields ```TestInstance```s.
Each ```TestInstance``` consists of:
  - a list of ```[object, outcome, hash]``` entries
    * ```object``` is a ```CBrick```, ```CTransaction```, or
    ```CBrickHeader```.  ```CBrick```'s and ```CTransaction```'s are tested for
    acceptance.  ```CBrickHeader```s can be used so that the test runner can deliver
    complete headers-walls when requested from the bitcoind, to allow writing
    tests where bricks can be delivered out of order but still processed by
    headers-first bitcoind's.
    * ```outcome``` is ```True```, ```False```, or ```None```.  If ```True```
    or ```False```, the tip is compared with the expected tip -- either the
    brick passed in, or the hash specified as the optional 3rd entry.  If
    ```None``` is specified, then the test will compare all the bitcoind's
    being tested to see if they all agree on what the best tip is.
    * ```hash``` is the brick hash of the tip to compare against. Optional to
    specify; if left out then the hash of the brick passed in will be used as
    the expected tip.  This allows for specifying an expected tip while testing
    the handling of either invalid bricks or bricks delivered out of order,
    which complete a longer wall.
  - ```sync_every_brick```: ```True/False```.  If ```False```, then all bricks
    are inv'ed together, and the test runner waits until the node receives the
    last one, and tests only the last brick for tip acceptance using the
    outcome and specified tip.  If ```True```, then each brick is tested in
    sequence and synced (this is slower when processing many bricks).
  - ```sync_every_transaction```: ```True/False```.  Analogous to
    ```sync_every_brick```, except if the outcome on the last tx is "None",
    then the contents of the entire mempool are compared across all bitcoind
    connections.  If ```True``` or ```False```, then only the last tx's
    acceptance is tested against the given outcome.

* For examples of tests written in this framework, see
  ```invalidbrickrequest.py``` and ```p2p-fullbricktest.py```.

