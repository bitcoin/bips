use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use log::debug;

// Add imports for the unified keypair
use bitcoin::secp256k1::{SecretKey, XOnlyPublicKey};
use bitcoinpqc::KeyPair;

/// Enum representing the type of leaf script to create
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafScriptType {
    /// Script requires only SLH-DSA signature
    SlhDsaOnly,
    /// Script requires only Schnorr signature  
    SchnorrOnly,
    /// Script requires both Schnorr and SLH-DSA signatures (in that order)
    ConcatenatedSchnorrAndSlhDsaSameLeaf,
    /// Leaves of TapTree are mixed.  Some leaves are locked using Schnorr and others are locked using SLH-DSA
    Mixed,
    /// Script type is not applicable
    NotApplicable,
}

impl LeafScriptType {
    /// Check if this script type uses SLH-DSA
    pub fn uses_slh_dsa(&self) -> bool {
        matches!(self, LeafScriptType::SlhDsaOnly | LeafScriptType::ConcatenatedSchnorrAndSlhDsaSameLeaf)
    }

    /// Check if this script type uses Schnorr
    pub fn uses_schnorr(&self) -> bool {
        matches!(self, LeafScriptType::SchnorrOnly | LeafScriptType::ConcatenatedSchnorrAndSlhDsaSameLeaf)
    }

    /// Check if this script type requires both signature types
    pub fn requires_both(&self) -> bool {
        matches!(self, LeafScriptType::ConcatenatedSchnorrAndSlhDsaSameLeaf)
    }

    /// Check if TapTree uses Schnorr for some leaves and SLH-DSA for others
    pub fn uses_mixed(&self) -> bool {
        matches!(self, LeafScriptType::Mixed)
    }

    /// Check if this script type is not applicable
    pub fn is_not_applicable(&self) -> bool {
        matches!(self, LeafScriptType::NotApplicable)
    }

    /// Convert to string representation for serialization
    pub fn to_string(&self) -> String {
        match self {
            LeafScriptType::SlhDsaOnly => "SLH_DSA_ONLY".to_string(),
            LeafScriptType::SchnorrOnly => "SCHNORR_ONLY".to_string(),
            LeafScriptType::ConcatenatedSchnorrAndSlhDsaSameLeaf => "CONCATENATED_SCHNORR_AND_SLH_DSA".to_string(),
            LeafScriptType::Mixed => "MIXED".to_string(),
            LeafScriptType::NotApplicable => "NOT_APPLICABLE".to_string(),
        }
    }

    /// Parse from string representation
    pub fn from_string(s: &str) -> Self {
        match s {
            "SLH_DSA_ONLY" => LeafScriptType::SlhDsaOnly,
            "SCHNORR_ONLY" => LeafScriptType::SchnorrOnly,
            "CONCATENATED_SCHNORR_AND_SLH_DSA" => LeafScriptType::ConcatenatedSchnorrAndSlhDsaSameLeaf,
            "MIXED" => LeafScriptType::Mixed,
            _ => LeafScriptType::NotApplicable,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TestVectors {
    pub version: u32,
    #[serde(rename = "test_vectors")]
    pub test_vectors: Vec<TestVector>,
    #[serde(skip, default = "HashMap::new")]
    pub test_vector_map: HashMap<String, TestVector>,
}

impl<'de> Deserialize<'de> for TestVectors {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            version: u32,
            #[serde(rename = "test_vectors")]
            test_vectors: Vec<TestVector>,
        }

        let helper = Helper::deserialize(deserializer)?;
        
        let mut test_vector_map = HashMap::new();
        for test in helper.test_vectors.iter() {
            test_vector_map.insert(test.id.clone(), test.clone());
        }

        Ok(TestVectors {
            version: helper.version,
            test_vectors: helper.test_vectors,
            test_vector_map,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TestVector {
    pub id: String,
    pub objective: String,
    pub given: TestVectorGiven,
    pub intermediary: TestVectorIntermediary,
    pub expected: TestVectorExpected,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TestVectorGiven {

    #[serde(rename = "internalPubkey")]
    pub internal_pubkey: Option<String>,

    #[serde(rename = "scriptTree")]
    pub script_tree: Option<TVScriptTree>,

    #[serde(rename = "scriptInputs")]
    pub script_inputs: Option<Vec<String>>,
    #[serde(rename = "scriptHex")]
    pub script_hex: Option<String>,
    #[serde(rename = "controlBlock")]
    pub control_block: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TestVectorIntermediary {

    #[serde(default)]
    #[serde(rename = "leafHashes")]
    pub leaf_hashes: Vec<String>,
    #[serde(rename = "merkleRoot")]
    pub merkle_root: Option<String>
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TestVectorExpected {
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: Option<String>,
    #[serde(rename = "bip350Address")]
    pub bip350_address: Option<String>,
    #[serde(default)]
    #[serde(rename = "scriptPathControlBlocks")]
    pub script_path_control_blocks: Option<Vec<String>>,
    #[serde(rename = "error")]
    pub error: Option<String>,
    #[serde(rename = "address")]
    pub address: Option<String>,
    #[serde(default)]
    pub witness: Option<String>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TVScriptLeaf {
    pub id: u8,
    pub script: String,
    #[serde(rename = "leafVersion")]
    pub leaf_version: u8,
}

// Taproot script trees are binary trees, so each branch should have exactly two children.
#[derive(Debug, Serialize, Clone)]
pub enum TVScriptTree {
    Leaf(TVScriptLeaf),
    Branch {

        // Box is used because Rust needs to know the exact size of types at compile time.
        // Without it, we'd have an infinitely size recursive type.
        // The enum itself is on the stack, but the Box fields within the Branch variant store pointers to heap-allocated ScriptTree values.
        left: Box<TVScriptTree>,
        right: Box<TVScriptTree>,
    },
}

// Add custom deserialize implementation
impl<'de> Deserialize<'de> for TVScriptTree {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Helper {
            Leaf(TVScriptLeaf),
            Branch(Vec<TVScriptTree>),
        }

        match Helper::deserialize(deserializer)? {
            Helper::Leaf(leaf) => Ok(TVScriptTree::Leaf(leaf)),
            Helper::Branch(v) => {
                assert!(v.len() == 2, "Branch must have exactly two children");
                let mut iter = v.into_iter();
                Ok(TVScriptTree::Branch {
                    left: Box::new(iter.next().unwrap()),
                    right: Box::new(iter.next().unwrap()),
                })
            }
        }
    }
}

// Add this enum before the TVScriptTree implementation
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Direction {
    Left,
    Right,
    Root,
}

impl TVScriptTree {
    /// Implements a "post-order" traversal as follows: left, right, branch
    pub fn traverse_with_depth<F: FnMut(&TVScriptTree, u8, Direction)>(&self, depth: u8, direction: Direction, f: &mut F) {
        match self {
            TVScriptTree::Branch { left, right } => {

                right.traverse_with_depth(depth, Direction::Right, f); // Pass Right for right subtree
                left.traverse_with_depth(depth, Direction::Left, f);   // Pass Left for left subtree
                f(self, depth, direction);  // Pass the current node's direction
            }
            TVScriptTree::Leaf { .. } => {
                f(self, depth, direction);
            }
        }
    }

    /// Traverses the tree visiting right subtree leaves first, then left subtree leaves.
    /// Depth increases by 1 at each branch level.
    /*
             root (depth 0)
            /            \
        L0 (depth 1)    (subtree) (depth 1)
                            /          \
                    L1 (depth 2)    L2 (depth 2)

        The new traversal will visit:
            L1 at depth 2 -> L2 at depth 2 -> L0 at depth 1
     */
    pub fn traverse_with_right_subtree_first<F: FnMut(&TVScriptTree, u8, Direction)>(&self, depth: u8, direction: Direction, f: &mut F) {
        match self {
            TVScriptTree::Branch { left, right } => {
                let next_depth = depth + 1;
                // Visit right subtree first
                right.traverse_with_right_subtree_first(next_depth, Direction::Right, f);
                // Then visit left subtree
                left.traverse_with_right_subtree_first(next_depth, Direction::Left, f);
            }
            TVScriptTree::Leaf { .. } => {
                f(self, depth, direction);
            }
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Direction::Left => write!(f, "L"),
            Direction::Right => write!(f, "R"),
            Direction::Root => write!(f, "Root"),
        }
    }
}

pub struct ScriptTreeHashCache {
    pub leaf_hashes: HashMap<String, String>,
    pub branch_hashes: HashMap<u8, String>,
}

impl ScriptTreeHashCache {
    pub fn new() -> Self {
        Self {
            leaf_hashes: HashMap::new(),
            branch_hashes: HashMap::new(),
        }
    }

    pub fn set_leaf_hash(&mut self, branch_id: u8, direction: Direction, hash: String) {
        let key = format!("{branch_id}_{direction}");
        debug!("set_leaf_hash: key: {}, hash: {}", key, hash);
        self.leaf_hashes.insert(key, hash);
    }

    pub fn set_branch_hash(&mut self, branch_id: u8, hash: String) {
        self.branch_hashes.insert(branch_id, hash);
    }
}

fn serialize_hex<S>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&hex::encode(bytes))
}

fn deserialize_hex<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    hex::decode(s).map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendDetails {
    pub tx_hex: String,
    #[serde(serialize_with = "serialize_hex")]
    #[serde(deserialize_with = "deserialize_hex")]
    pub sighash: Vec<u8>,
    #[serde(serialize_with = "serialize_hex")]
    #[serde(deserialize_with = "deserialize_hex")]
    pub sig_bytes: Vec<u8>,
    #[serde(serialize_with = "serialize_hex")]
    #[serde(deserialize_with = "deserialize_hex")]
    pub derived_witness_vec: Vec<u8>,
}

impl std::process::Termination for SpendDetails {
    fn report(self) -> std::process::ExitCode {
        if let Ok(json) = serde_json::to_string_pretty(&self) {
            println!("{}", json);
        } else {
            println!("{:?}", self);
        }
        std::process::ExitCode::SUCCESS
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoReturn {

    pub script_pubkey_hex: String,
    pub bech32m_address: String,
    pub bitcoin_network: bitcoin::Network,
}

impl std::process::Termination for UtxoReturn {
    fn report(self) -> std::process::ExitCode {
        if let Ok(json) = serde_json::to_string_pretty(&self) {
            println!("{}", json);
        } else {
            println!("{:?}", self);
        }
        std::process::ExitCode::SUCCESS
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaptreeReturn {
    pub leaf_script_priv_keys_hex: Vec<String>, // Changed to support multiple private keys
    pub leaf_script_hex: String,
    pub tree_root_hex: String,
    pub control_block_hex: String,
    /// The script type of the leaf being returned (needed for spending)
    pub leaf_script_type: String,
}

impl std::process::Termination for TaptreeReturn {
    fn report(self) -> std::process::ExitCode {
        if let Ok(json) = serde_json::to_string_pretty(&self) {
            println!("{}", json);
        } else {
            println!("{:?}", self);
        }
        std::process::ExitCode::SUCCESS
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructionReturn {
    pub taptree_return: TaptreeReturn,
    pub utxo_return: UtxoReturn,
}

impl std::process::Termination for ConstructionReturn {
    fn report(self) -> std::process::ExitCode {
        if let Ok(json) = serde_json::to_string_pretty(&self) {
            println!("{}", json);
        } else {
            println!("{:?}", self);
        }
        std::process::ExitCode::SUCCESS
    }
}

/// A unified keypair that can contain either a Schnorr keypair or an SLH-DSA keypair
#[derive(Debug, Clone)]
pub enum UnifiedKeypair {
    Schnorr(SecretKey, XOnlyPublicKey),
    SlhDsa(KeyPair),
}

/// A container for multiple keypairs that can be used in a single leaf script
#[derive(Debug, Clone)]
pub struct MultiKeypair {
    pub schnorr_keypair: Option<UnifiedKeypair>,
    pub slh_dsa_keypair: Option<UnifiedKeypair>,
}

impl MultiKeypair {
    /// Create a new MultiKeypair with only a Schnorr keypair
    pub fn new_schnorr_only(schnorr_keypair: UnifiedKeypair) -> Self {
        Self {
            schnorr_keypair: Some(schnorr_keypair),
            slh_dsa_keypair: None,
        }
    }

    /// Create a new MultiKeypair with only an SLH-DSA keypair
    pub fn new_slh_dsa_only(slh_dsa_keypair: UnifiedKeypair) -> Self {
        Self {
            schnorr_keypair: None,
            slh_dsa_keypair: Some(slh_dsa_keypair),
        }
    }

    /// Create a new MultiKeypair with both keypairs
    pub fn new_combined(schnorr_keypair: UnifiedKeypair, slh_dsa_keypair: UnifiedKeypair) -> Self {
        Self {
            schnorr_keypair: Some(schnorr_keypair),
            slh_dsa_keypair: Some(slh_dsa_keypair),
        }
    }

    /// Get all secret key bytes for serialization (in order: schnorr, then slh_dsa if present)
    pub fn secret_key_bytes(&self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        if let Some(ref schnorr) = self.schnorr_keypair {
            result.push(schnorr.secret_key_bytes());
        }
        if let Some(ref slh_dsa) = self.slh_dsa_keypair {
            result.push(slh_dsa.secret_key_bytes());
        }
        result
    }

    /// Get all public key bytes for script construction (in order: schnorr, then slh_dsa if present)
    pub fn public_key_bytes(&self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        if let Some(ref schnorr) = self.schnorr_keypair {
            result.push(schnorr.public_key_bytes());
        }
        if let Some(ref slh_dsa) = self.slh_dsa_keypair {
            result.push(slh_dsa.public_key_bytes());
        }
        result
    }

    /// Check if this contains a Schnorr keypair
    pub fn has_schnorr(&self) -> bool {
        self.schnorr_keypair.is_some()
    }

    /// Check if this contains an SLH-DSA keypair
    pub fn has_slh_dsa(&self) -> bool {
        self.slh_dsa_keypair.is_some()
    }

    /// Get the Schnorr keypair if present
    pub fn schnorr_keypair(&self) -> Option<&UnifiedKeypair> {
        self.schnorr_keypair.as_ref()
    }

    /// Get the SLH-DSA keypair if present
    pub fn slh_dsa_keypair(&self) -> Option<&UnifiedKeypair> {
        self.slh_dsa_keypair.as_ref()
    }
}

/// Information about a single leaf in a mixed-type tree
/// Used when different leaves in the same tree use different algorithms
#[derive(Debug, Clone)]
pub struct MixedLeafInfo {
    /// The leaf index in the tree
    pub leaf_index: u32,
    /// The script type for this specific leaf
    pub leaf_script_type: LeafScriptType,
    /// The keypairs for this leaf
    pub keypairs: MultiKeypair,
    /// The script for this leaf
    pub script: Vec<u8>,
}

impl MixedLeafInfo {
    /// Create a new MixedLeafInfo for a Schnorr-only leaf
    pub fn new_schnorr(leaf_index: u32, keypairs: MultiKeypair, script: Vec<u8>) -> Self {
        Self {
            leaf_index,
            leaf_script_type: LeafScriptType::SchnorrOnly,
            keypairs,
            script,
        }
    }

    /// Create a new MixedLeafInfo for an SLH-DSA-only leaf
    pub fn new_slh_dsa(leaf_index: u32, keypairs: MultiKeypair, script: Vec<u8>) -> Self {
        Self {
            leaf_index,
            leaf_script_type: LeafScriptType::SlhDsaOnly,
            keypairs,
            script,
        }
    }

    /// Create a new MixedLeafInfo for a combined Schnorr+SLH-DSA leaf
    pub fn new_combined(leaf_index: u32, keypairs: MultiKeypair, script: Vec<u8>) -> Self {
        Self {
            leaf_index,
            leaf_script_type: LeafScriptType::ConcatenatedSchnorrAndSlhDsaSameLeaf,
            keypairs,
            script,
        }
    }

    /// Get the secret key bytes for this leaf
    pub fn secret_key_bytes(&self) -> Vec<Vec<u8>> {
        self.keypairs.secret_key_bytes()
    }

    /// Get the public key bytes for this leaf
    pub fn public_key_bytes(&self) -> Vec<Vec<u8>> {
        self.keypairs.public_key_bytes()
    }
}

impl UnifiedKeypair {
    /// Create a new Schnorr keypair
    pub fn new_schnorr(secret_key: SecretKey, public_key: XOnlyPublicKey) -> Self {
        UnifiedKeypair::Schnorr(secret_key, public_key)
    }

    /// Create a new SLH-DSA keypair
    pub fn new_slh_dsa(keypair: KeyPair) -> Self {
        UnifiedKeypair::SlhDsa(keypair)
    }

    /// Get the secret key bytes for serialization
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        match self {
            UnifiedKeypair::Schnorr(secret_key, _) => secret_key.secret_bytes().to_vec(),
            UnifiedKeypair::SlhDsa(keypair) => keypair.secret_key.bytes.clone(),
        }
    }

    /// Get the public key bytes for script construction
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            UnifiedKeypair::Schnorr(_, public_key) => public_key.serialize().to_vec(),
            UnifiedKeypair::SlhDsa(keypair) => keypair.public_key.bytes.clone(),
        }
    }

    /// Get the algorithm type
    pub fn algorithm(&self) -> &'static str {
        match self {
            UnifiedKeypair::Schnorr(_, _) => "Schnorr",
            UnifiedKeypair::SlhDsa(_) => "SLH-DSA",
        }
    }

    /// Check if this is a Schnorr keypair
    pub fn is_schnorr(&self) -> bool {
        matches!(self, UnifiedKeypair::Schnorr(_, _))
    }

    /// Check if this is an SLH-DSA keypair
    pub fn is_slh_dsa(&self) -> bool {
        matches!(self, UnifiedKeypair::SlhDsa(_))
    }

    /// Get the underlying Schnorr keypair if this is a Schnorr keypair
    pub fn as_schnorr(&self) -> Option<(&SecretKey, &XOnlyPublicKey)> {
        match self {
            UnifiedKeypair::Schnorr(secret_key, public_key) => Some((secret_key, public_key)),
            _ => None,
        }
    }

    /// Get the underlying SLH-DSA keypair if this is an SLH-DSA keypair
    pub fn as_slh_dsa(&self) -> Option<&KeyPair> {
        match self {
            UnifiedKeypair::SlhDsa(keypair) => Some(keypair),
            _ => None,
        }
    }
}
