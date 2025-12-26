*P2QRH specific changes to rust-bitcoin*

# 1. p2qrh module

The p2qrh branch of rust-bitcoin includes a new module: `p2qrh`.

Source code for this new module can be found [here](https://github.com/jbride/rust-bitcoin/blob/p2qrh/bitcoin/src/p2qrh/mod.rs).

Highlights of this _p2qrh_ module as follows:

## 1.1. P2qrhBuilder

This is struct inherits from the rust-bitcoin _TaprootBuilder_.
It has an important modification in that it disables keypath spend.

Similar to its Taproot parent, P2qrhBuilder provides functionality to add leaves to a TapTree.
One its TapTree has been fully populated with all leaves, an instance of _P2qrhSpendInfo_ can be retrieved from P2qrhBuilder.


```
pub struct P2qrhBuilder {
    inner: TaprootBuilder
}

impl P2qrhBuilder {

    /// Creates a new P2QRH builder.
    pub fn new() -> Self {
        Self {
            inner: TaprootBuilder::new()
        }
    }

    /// Adds a leaf to the P2QRH builder.
    pub fn add_leaf_with_ver(
        self,
        depth: u8,
        script: ScriptBuf,
        leaf_version: LeafVersion,
    ) -> Result<Self, P2qrhError> {
        match self.inner.add_leaf_with_ver(depth, script, leaf_version) {
            Ok(builder) => Ok(Self { inner: builder }),
            Err(_) => Err(P2qrhError::LeafAdditionError)
        }
    }

    /// Finalizes the P2QRH builder.
    pub fn finalize(self) -> Result<P2qrhSpendInfo, P2qrhError> {
        let node_info: NodeInfo = self.inner.try_into_node_info().unwrap();
        Ok(P2qrhSpendInfo {
            merkle_root: Some(node_info.node_hash()),
            //script_map: self.inner.script_map().clone(),
        })
    }

    /// Converts the P2QRH builder into a Taproot builder.
    pub fn into_inner(self) -> TaprootBuilder {
        self.inner
    }
}
```

##  1.2. P2qrhSpendInfo

Provides merkle_root of a completed P2qrh TapTree

```
/// A struct for P2QRH spend information.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct P2qrhSpendInfo {

    /// The merkle root of the script path.
    pub merkle_root: Option<TapNodeHash>

}
```

## 1.3. P2qrhScriptBuf

Allows for creation of a P2QRH scriptPubKey UTXO using only the merkle root of a script tree only.

```
/// A wrapper around ScriptBuf for P2QRH (Pay to Quantum Resistant Hash) scripts.
pub struct P2qrhScriptBuf {
    inner: ScriptBuf
}

impl P2qrhScriptBuf {
    /// Creates a new P2QRH script from a ScriptBuf.
    pub fn new(inner: ScriptBuf) -> Self {
        Self { inner }
    }
    
    /// Generates P2QRH scriptPubKey output
    /// Only accepts the merkle_root (of type TapNodeHash)
    /// since keypath spend is disabled in p2qrh
    pub fn new_p2qrh(merkle_root: TapNodeHash) -> Self {
        // https://github.com/cryptoquick/bips/blob/p2qrh/bip-0360.mediawiki#scriptpubkey
        let merkle_root_hash_bytes: [u8; 32] = merkle_root.to_byte_array();
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_3)

            // automatically pre-fixes with OP_PUSHBYTES_32 (as per size of hash)
            .push_slice(&merkle_root_hash_bytes)
            
            .into_script();
        P2qrhScriptBuf::new(script)
    }

    /// Returns the script as a reference.
    pub fn as_script(&self) -> &Script {
        self.inner.as_script()
    }
}
```

## 1.4. P2QRH Control Block

Closely related to P2TR control block.
Difference being that _internal public key_ is not included.


```
/// A control block for P2QRH (Pay to Quantum Resistant Hash) script path spending.
/// This is a simplified version of Taproot's control block that excludes key-related fields.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct P2qrhControlBlock {
    /// The version of the leaf.
    pub leaf_version: LeafVersion,
    /// The merkle branch of the leaf.
    pub merkle_branch: TaprootMerkleBranch,
}
```

# 2. Witness Program

New p2qrh related functions that allow for creation of a new V3 _witness program_ given a merkle_root only.

Found in bitcoin/src/blockdata/script/witness_program.rs

```
/// Creates a [`WitnessProgram`] from a 32 byte merkle root.
fn new_p2qrh(program: [u8; 32]) -> Self {
    WitnessProgram { version: WitnessVersion::V3, program: ArrayVec::from_slice(&program) }
}

/// Creates a pay to quantum resistant hash address from a merkle root.
pub fn p2qrh(merkle_root: Option<TapNodeHash>) -> Self {
    let merkle_root = merkle_root.unwrap();
    WitnessProgram::new_p2qrh(merkle_root.to_byte_array())
}
```

# 3. Address

New _p2qrh_ function that allows for creation of a new _p2qrh_ Address given a merkle_root only.

Found in bitcoin/src/address/mod.rs

```
/// Creates a pay to quantum resistant hash address from a merkle root.
pub fn p2qrh(merkle_root: Option<TapNodeHash>, hrp: impl Into<KnownHrp>) -> Address {
    let program = WitnessProgram::p2qrh(merkle_root);
    Address::from_witness_program(program, hrp)
}
```
