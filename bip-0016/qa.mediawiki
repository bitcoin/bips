This page is a Quality Assurance test plan for [[../bip-0016.mediawiki|BIP 16]].  If you see a test missing, please add it.
If you can help test, please edit this page to sign-off on it.

{| class="wikitable"
|-
! Done !! Test Procedure !! Tested by

|- style="color:green;"
| &#x2713;
| Run BIP-16-capable Bitcoin 0.6 on testnet and main net<br />
Send coins using GUI, RCP sendtoaddress, and RCP sendmany commands<br />
Result: coins sent in all cases
| Gavin Andresen

|- style="color:green;"
| &#x2713;
| Test multisig 1-of-1<br />
Run 0.6 bitcoind, get a public key with: ./bitcoind -testnet validateaddress $(./bitcoind -testnet getnewaddress)<br />
Generate a multisig 1-of-1 address: ./bitcoind addmultisigaddress 1 {public key from above}<br />
Send-to-self some bitcoins using that address<br />
Result: transaction is confirmed by network, displays properly in listtransactions.
Result: balance is unaffected
| Gavin Andresen; see transactions in [http://blockexplorer.com/testnet/block/000000001bdceba3936f2ea6a55311ac7b6030e327f1960e892620fcde6abf5f testnet block 44989]


|- style="color:green;"
| &#x2713;
| Test multisig 1-of-2<br />
Run 0.6 bitcoind, get 2 new bitcoin addresses<br />
Generate a multisig 1-of-2 address: ./bitcoind addmultisigaddress 1 {address1} {address2}<br />
Send-to-self some bitcoins using that address<br />
Result: transaction is confirmed by network, displays properly in listtransactions.
Result: bitcoin balance is unaffected.
| Gavin Andresen; see transactions in [http://blockexplorer.com/testnet/block/000000001bdceba3936f2ea6a55311ac7b6030e327f1960e892620fcde6abf5f testnet block 44989]


|- style="color:green;"
| &#x2713;
| Test multisig 1-of-3, 2-of-3, 3-of-3<br />
Repeat test procedures above, with the other new multisignature transaction types
| Gavin Andresen; see transactions in [http://blockexplorer.com/testnet/block/000000001bdceba3936f2ea6a55311ac7b6030e327f1960e892620fcde6abf5f testnet block 44989]

|- style="color:green;"
| &#x2713;
| Test multisig send-to-other<br />
Repeat test procedures above, but use two bitcoinds, prepared as follows:<br />
bitcoind 1 : Run getnewaddress and addmultisigaddress<br />
bitcoind 2 : Just addmultisigaddress<br />
Send coins from 2 to 1 using the address<br />
Result: transaction is accepted/confirmed by network<br />
Result: balance for 2 goes down, listtransactions for 2 displays correct result<br />
Result: balance for 1 goes up, listtransactions for 1 displays correct result<br />
| Gavin Andresen; see transactions in [http://blockexplorer.com/testnet/block/000000001bdceba3936f2ea6a55311ac7b6030e327f1960e892620fcde6abf5f testnet block 44989]


|- style="color:green;"
| &#x2713;
| Test redeeming multisignature transactions<br />
Fund a new, empty wallet entirely with multisig transactions<br />
Wait for transactions to confirm<br />
Use sendtoaddress and sendmany to generate spend-from-multisig transactions<br />
Spend to both single-address and multisig address, and test send-to-other and send-to-self<br />
Result: transactions are accepted/confirmed by network<br />
Result: balance decreases, listtransactions displays correct information<br />
| Gavin Andresen; see transactions in [http://blockexplorer.com/testnet/block/000000001bdceba3936f2ea6a55311ac7b6030e327f1960e892620fcde6abf5f testnet block 44989]


|- style="color:green;"
| &#x2713;
| Run 0.6 Bitcoin-Qt GUI on one of the test wallets from above<br />
Result: balance and transactions displayed correctly
| Gavin Andresen

|- style="color:orange;"
| &#x2713;
| Run BIP-16-capable backport Bitcoin 0.3.19 through 0.5.1 on testnet and main net<br />
Send coins using GUI, RCP sendtoaddress, and RCP sendmany commands<br />
Result: coins sent in all cases
| Gavin Andresen (tested 0.3.19, 0.3.24 and 0.5.1)

|- style="color:green;"
| &#x2713;
| Run BIP-16-capable Bitcoin 0.6.0 on testnet<br />
Mine coins using built-in miner<br />
Result: blocks accepted, show up on blockexplorer.com/testnet<br />
Result: mined blocks' coinbase contains /P2SH/ string
| Gavin Andresen

|- style="color:green;"
| &#x2713;
| Run BIP-16-capable Bitcoin 0.6.0 on testnet<br />
Mine coins using getwork interface<br />
Result: blocks accepted, show up on blockexplorer.com/testnet<br />
Result: mined blocks' coinbase contains /P2SH/ string
| Gavin Andresen

|- style="color:green;"
|
| Run BIP-16-capable Bitcoin 0.6.0 on testnet<br />
Mine coins using getmemorypool interface<br />
Result: blocks accepted, show up on blockexplorer.com/testnet<br />
Result: mined blocks' coinbase contains /P2SH/ string
| Gregory Maxwell; Using p2pool see [https://blockexplorer.com/testnet/rawblock/00000000040367fcb750b6f064db6955b6c7c6218fb625e3dfed6b5c19c97107 testnet block 45400] (and many others, also tested on mainnet) 

|- style="color:green;"
| &#x2713;
| Run BIP-16-capable Bitcoin 0.3.19 through 0.5.1 backports on testnet<br />
Mine coins using built-in miner<br />
Result: blocks accepted, show up on blockexplorer.com/testnet<br />
Result: mined blocks' coinbase contains /P2SH/ string
| Gavin Andresen (tested all on a testnet-in-a-box)

|- style="color:green;"
| &#x2713;
| Run BIP-16-capable Bitcoin 3.19 through 0.5.1 backports on testnet<br />
Mine coins using getwork interface<br />
Result: blocks accepted, show up on blockexplorer.com/testnet<br />
Result: mined blocks' coinbase contains /P2SH/ string
| Gavin Andresen (tested all on a testnet-in-a-box)

|- style="color:green;"
| &#x2713;
| Run BIP-16-capable Bitcoin 0.3.19 through 0.5.1 backports on testnet<br />
Mine coins using built-in miner<br />
Result: blocks accepted, show up on blockexplorer.com/testnet<br />
Result: mined blocks' coinbase contains /P2SH/ string
| Gavin Andresen (tested all on a testnet-in-a-box)

|- style="color:green;"
| &#x2713;
| Run BIP-16-capable Bitcoin 3.19 through 0.5.1 backports on testnet<br />
Mine coins using getwork interface<br />
Result: blocks accepted, show up on blockexplorer.com/testnet<br />
Result: mined blocks' coinbase contains /P2SH/ string
| Gavin Andresen (tested all on a testnet-in-a-box)
|- style="color:red;"

|- style="color:red;"
|
| Run BIP-16-capable Bitcoin 3.19 through 0.5.1 backports on testnet<br />
Mine coins using getmemorypool interface<br />
Result: blocks accepted, show up on blockexplorer.com/testnet<br />
Result: mined blocks' coinbase contains /P2SH/ string
| 

|- style="color:green;"
| &#x2713;
| Create/run unit tests for:<br />
multisignature signing/verification<br />
multisignature invalid signature failure<br />
multisignature IsStandard() success/failure<br />
extraction of addresses from multisignature transactions<br />
BIP 16 IsStandard() success/failure (including failure with OP_PUSHDATA1/2/4)<br />
BIP 16 AreInputsStandard() success/failure<br />
BIP 16 compatibility with other 3 standard transaction types<br />
BIP 16 no-recursion test<br />
BIP 16 switchover date logic<br />
OP_CHECKMULTISIG counting of signature operations inside BIP 16 transactions<br />
| Gavin Andresen (see test/multisig_tests.cpp, test/script_tests.cpp, test/script_P2SH_tests.cpp, test/sigopcount_tests.cpp in the bitcoin source tree; 'make test_bitcoin' in src/ directory to compile)

|- style="color:green;"
| &#x2713;
| Create/run 'transaction fuzzer' to stress-test BIP 16 transactions
| Gavin Andresen (https://github.com/gavinandresen/bitcoin-git/tree/fuzzer , run twice on both testnet-in-a-box and testnet with 100,000 'fuzzed' transactions each test run) Valid fuzzed transactions appeared in (for example) [http://blockexplorer.com/testnet/block/000000001587c859649cea954e921ba4efd77707fb327dd53e122fd7b89636c4 testnet block 44987]

|- style="color:green;"
| &#x2713;
| Run Bitcoin 0.6 on main net <br />
Result: blocks created properly
Result: blocks include /P2SH/ string in their coinbase
| various mining pools

|- style="color:green;"
| &#x2713;
| Run BIP 16 vinced_mergedmine backport on main net <br />
Result: blocks created properly
Result: blocks include /P2SH/ string in their coinbase
| (Gavin for slush: after bug fixes, running with no issues)<br />

|- style="color:green;"
| &#x2713;
| Test chain-split handling on testnet-in-a-box <br />
Create two valid hash, invalid signature transactions in two blocks separated in time on a testnet-in-a-box chain<br />
Run a bitcoind to synchronize with the chain, with -paytoscripthashtime set in between the two blocks<br/>
Result: first transaction/block accepted, second causes a chain split<br/>
Re-run bitcoind with -paytoscripthashtime in the future<br/>
Result: entire chain accepted
| Gavin Andresen: testnet-in-a-box files at: http://www.skypaint.com/bitcoin/bip16chain.tar.gz first half-valid BIP16 transaction at block 2431 (time 1328202835) second at block 2436 (time 1328204241)<br />

|}
