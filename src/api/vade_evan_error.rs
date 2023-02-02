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
    #[error("pubkey for verification method not found, {0}")]
    InvalidVerificationMethod(String),
    #[error("JSON (de)serialization failed")]
    JsonDeSerialization(#[from] serde_json::Error),
    #[error("JSON-ld handling failed, {0}")]
    JsonLdHandling(String),
    // how to say "we need a separate error type" without saying "we need a separate error type":
    #[cfg(feature = "plugin-vc-zkp-bbs")]
    #[error("base64 decoding failed")]
    Base64DecodingFailed(#[from] base64::DecodeError),
    #[cfg(feature = "plugin-vc-zkp-bbs")]
    #[error("an error has occurred during bbs signature validation: {0}")]
    BbsValidationError(String),
    #[cfg(feature = "plugin-vc-zkp-bbs")]
    #[error("could not parse public key: {0}")]
    PublicKeyParsingError(String),
    #[cfg(feature = "plugin-vc-zkp-bbs")]
    #[error("revocation list invalid; {0}")]
    RevocationListInvalid(String),
    #[cfg(feature = "plugin-vc-zkp-bbs")]
    #[error("credential has been revoked")]
    CredentialRevoked,
    #[cfg(feature = "plugin-vc-zkp-bbs")]
    #[error("wrong number of messages in credential, got {0} but proof was created for {1}")]
    MessageCountMismatch(usize, usize),
}
impl From<Box<dyn std::error::Error>> for VadeEvanError {
    fn from(vade_error: Box<dyn std::error::Error>) -> VadeEvanError {
        VadeEvanError::InternalError {
            source_message: vade_error.to_string(),
        }
    }
}
