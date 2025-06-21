
# p2qrh test vectors

This rust project contains the test vectors for BIP-360


## Local Development

These test vectors are being developed in conjunction with forks of [rust-bitcoin](https://github.com/jbride/rust-bitcoin/tree/p2qrh) and [rust-miniscript](https://github.com/jbride/rust-miniscript/tree/p2qrh) customized with p2qrh functionality.
As such, these test vectors assume the presence of these customized forks cloned to your local environment. 

1. create soft-link to your `rust-bitcoin` clone: 
   ```
   $ ln -s /path/to/git/clone/of/rust-bitcoin
   ```

1. create soft-link to your `rust-miniscript` clone: 
   ```
   $ ln -s /path/to/git/clone/of/rust-miniscript
   ```

1. run a specific test:
   ```
   $ cargo test test_p2qrh_single_leaf_script_tree -- --nocapture
   ```

