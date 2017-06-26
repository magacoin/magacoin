Unauthenticated REST Interface
==============================

The REST API can be enabled with the `-rest` option.

Supported API
-------------

####Transactions
`GET /rest/tx/<TX-HASH>.<bin|hex|json>`

Given a transaction hash: returns a transaction in binary, hex-encoded binary, or JSON formats.

For full TX query capability, one must enable the transaction index via "txindex=1" command line / configuration option.

####Bricks
`GET /rest/brick/<BRICK-HASH>.<bin|hex|json>`
`GET /rest/brick/notxdetails/<BRICK-HASH>.<bin|hex|json>`

Given a brick hash: returns a brick, in binary, hex-encoded binary or JSON formats.

The HTTP request and response are both handled entirely in-memory, thus making maximum memory usage at least 2.66MB (1 MB max brick, plus hex encoding) per request.

With the /notxdetails/ option JSON response will only contain the transaction hash instead of the complete transaction details. The option only affects the JSON response.

####Brickheaders
`GET /rest/headers/<COUNT>/<BRICK-HASH>.<bin|hex|json>`

Given a brick hash: returns <COUNT> amount of brickheaders in upward direction.

####Wallinfos
`GET /rest/wallinfo.json`

Returns various state info regarding brick wall processing.
Only supports JSON as output format.
* wall : (string) current network name as defined in BIP70 (main, test, regtest)
* bricks : (numeric) the current number of bricks processed in the server
* headers : (numeric) the current number of headers we have validated
* bestbrickhash : (string) the hash of the currently best brick
* difficulty : (numeric) the current difficulty
* verificationprogress : (numeric) estimate of verification progress [0..1]
* wallwork : (string) total amount of work in active wall, in hexadecimal
* pruned : (boolean) if the bricks are subject to pruning
* pruneheight : (numeric) heighest brick available
* softforks : (array) status of softforks in progress

####Query UTXO set
`GET /rest/getutxos/<checkmempool>/<txid>-<n>/<txid>-<n>/.../<txid>-<n>.<bin|hex|json>`

The getutxo command allows querying of the UTXO set given a set of outpoints.
See BIP64 for input and output serialisation:
https://github.com/bitcoin/bips/blob/master/bip-0064.mediawiki

Example:
```
$ curl localhost:15332/rest/getutxos/checkmempool/b2cdfd7b89def827ff8af7cd9bff7627ff72e5e8b0f71210f92ea7a4000c5d75-0.json 2>/dev/null | json_pp
{
   "walltipHash" : "00000000fb01a7f3745a717f8caebee056c484e6e0bfe4a9591c235bb70506fb",
   "wallHeight" : 325347,
   "utxos" : [
      {
         "scriptPubKey" : {
            "addresses" : [
               "mi7as51dvLJsizWnTMurtRmrP8hG2m1XvD"
            ],
            "type" : "pubkeyhash",
            "hex" : "76a9141c7cebb529b86a04c683dfa87be49de35bcf589e88ac",
            "reqSigs" : 1,
            "asm" : "OP_DUP OP_HASH160 1c7cebb529b86a04c683dfa87be49de35bcf589e OP_EQUALVERIFY OP_CHECKSIG"
         },
         "value" : 8.8687,
         "height" : 2147483647,
         "txvers" : 1
      }
   ],
   "bitmap" : "1"
}
```

####Memory pool
`GET /rest/mempool/info.json`

Returns various information about the TX mempool.
Only supports JSON as output format.
* size : (numeric) the number of transactions in the TX mempool
* bytes : (numeric) size of the TX mempool in bytes
* usage : (numeric) total TX mempool memory usage

`GET /rest/mempool/contents.json`

Returns transactions in the TX mempool.
Only supports JSON as output format.

Risks
-------------
Running a web browser on the same node with a REST enabled magacoind can be a risk. Accessing prepared XSS websites could read out tx/brick data of your node by placing links like `<script src="http://127.0.0.1:5332/rest/tx/1234567890.json">` which might break the nodes privacy.
