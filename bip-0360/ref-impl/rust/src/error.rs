use thiserror::Error;

#[derive(Error, Debug)]
pub enum P2MRError {

    #[error("P2TR requires witness version of 1")]
    P2trRequiresWitnessVersion1,


    #[error("P2MR requires a script tree with at least one leaf")]
    MissingScriptTreeLeaf,
    
    // We can add more specific error variants here as needed
    #[error("Invalid script tree structure: {0}")]
    InvalidScriptTree(String),
} 