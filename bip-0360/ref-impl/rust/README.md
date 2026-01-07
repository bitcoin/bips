
# p2tsh test vectors

This rust project contains the test vectors for BIP-360


## Run Test Vectors

These test vectors are being developed in conjunction with forks of [rust-bitcoin](https://github.com/jbride/rust-bitcoin/tree/p2tsh) and [rust-miniscript](https://github.com/jbride/rust-miniscript/tree/p2tsh-pqc) customized with p2tsh functionality.


1. environment variables
   ```
   // Specify Bitcoin network used when generating bip350 (bech32m) address
   // Options: regtest, testnet, signet
   // Default: mainnet
   $ export BITCOIN_NETWORK=<regtest | testnet | signet >
   ```

1. run a specific test:
   ```
   $ cargo test test_p2tsh_single_leaf_script_tree -- --nocapture
   ```

## Local Development


All P2TSH/PQC enabled bitcoin crates are temporarily available in a custom crate registry at:  `https://crates.denver.space`.
These crates will be made available in `crates.io` in the near future.

Subsequently, you will need to execute the following at the root of your rust workspace:

```bash
mkdir .cargo \
    && echo '[registries.kellnr-denver-space]
index = "sparse+https://crates.denver.space/api/v1/crates/"' > .cargo/config
```

Afterwards, for all P2TSH/PQC enabled dependencies used in your project, include a "registry" similar to the following:

```bash
bitcoin = { version="0.32.6", registry = "kellnr-denver-space" }
```


