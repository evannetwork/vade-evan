#[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
use crate::helpers::CredentialError;
use crate::helpers::PresentationError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VadeEvanError {
    #[error("initialization failed with {source_message}")]
    InitializationFailed { source_message: String },
    #[error("vade call failed with: {source_message}")]
    InternalError { source_message: String },
    #[error("vade call returned no results")]
    NoResults,
    #[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
    #[error(transparent)]
    PresentationError(#[from] PresentationError),
}

impl From<Box<dyn std::error::Error>> for VadeEvanError {
    fn from(vade_error: Box<dyn std::error::Error>) -> VadeEvanError {
        VadeEvanError::InternalError {
            source_message: vade_error.to_string(),
        }
    }
}
