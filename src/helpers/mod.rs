#[cfg(feature = "plugin-vc-zkp-bbs")]
mod credential;
mod datatypes;
#[cfg(feature = "plugin-did-sidetree")]
mod did;
mod version_info;

#[cfg(feature = "plugin-vc-zkp-bbs")]
pub(crate) use credential::{Credential, CredentialError};
#[cfg(feature = "plugin-did-sidetree")]
pub(crate) use did::Did;
pub(crate) use version_info::VersionInfo;
