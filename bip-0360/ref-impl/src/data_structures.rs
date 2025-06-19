use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use log::debug;

#[derive(Debug, Serialize)]
pub struct TestVectors {
    pub version: u32,
    #[serde(rename = "test_vectors")]
    pub test_vectors: Vec<TestVector>,
    #[serde(skip, default = "HashMap::new")]
    pub test_vector_map: HashMap<String, TestVector>,
}

impl TestVectors {
    fn new() -> Self {
        Self {
            version: 0,
            test_vectors: Vec::new(),
            test_vector_map: HashMap::new(),
        }
    }
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