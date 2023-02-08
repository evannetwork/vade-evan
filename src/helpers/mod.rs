#[cfg(feature = "plugin-vc-zkp-bbs")]
mod credential;
mod datatypes;
mod did;
mod version_info;

#[cfg(feature = "capability-did-write")]
pub(crate) use did::DID;
#[cfg(feature = "plugin-vc-zkp-bbs")]
pub(crate) use credential::{Credential, CredentialError};
#[cfg(feature = "plugin-vc-zkp-bbs")]
pub use datatypes::IdentityDidDocument;
pub(crate) use version_info::VersionInfo;
