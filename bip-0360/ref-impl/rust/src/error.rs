use thiserror::Error;

#[derive(Error, Debug)]
pub enum P2QRHError {
    #[error("P2QRH requires a script tree with at least one leaf")]
    MissingScriptTreeLeaf,
    
    // We can add more specific error variants here as needed
    #[error("Invalid script tree structure: {0}")]
    InvalidScriptTree(String),
} 