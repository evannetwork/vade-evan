#[cfg(feature = "plugin-vc-zkp-bbs")]
mod credential;
mod datatypes;
mod did;
mod version_info;

#[cfg(feature = "plugin-vc-zkp-bbs")]
pub(crate) use credential::Credential;
pub(crate) use datatypes::*;
pub(crate) use did::DID;
pub(crate) use version_info::VersionInfo;
