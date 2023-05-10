#[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
mod credential;
mod datatypes;
#[cfg(feature = "did-sidetree")]
mod did;
#[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
mod presentation;
#[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
mod shared;
mod version_info;

#[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
pub(crate) use credential::{Credential, CredentialError};
#[cfg(feature = "did-sidetree")]
pub(crate) use did::Did;
#[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
pub(crate) use presentation::{Presentation, PresentationError};
pub(crate) use version_info::VersionInfo;
