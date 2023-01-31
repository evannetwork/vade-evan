use thiserror::Error;

#[derive(Error, Debug)]
pub enum VadeEvanError {
    #[error("initialization failed with {source_message}")]
    InitializationFailed { source_message: String },
    #[error("vade call failed with: {source_message}")]
    InternalError { source_message: String },
    #[error("vade call returned no results")]
    NoResults,
    #[error("invalid did document")]
    InvalidDidDocument(String),
    #[error("pubkey for verification method not found")]
    InvalidVerificationMethod(String),
    #[error("JSON (de)serialization failed")]
    JsonDeSerialization(#[from] serde_json::Error),
    #[error("JSON-ld handling failed, {0}")]
    JsonLdHandling(String),
}
impl From<Box<dyn std::error::Error>> for VadeEvanError {
    fn from(vade_error: Box<dyn std::error::Error>) -> VadeEvanError {
        VadeEvanError::InternalError {
            source_message: vade_error.to_string(),
        }
    }
}
