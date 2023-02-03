mod version_info;

#[cfg(feature = "plugin-vc-zkp-bbs")]
mod credential;
#[cfg(feature = "plugin-vc-zkp-bbs")]
mod datatypes;

#[cfg(feature = "plugin-vc-zkp-bbs")]
pub(crate) use credential::Credential;
#[cfg(feature = "plugin-vc-zkp-bbs")]
pub use datatypes::IdentityDidDocument;
pub(crate) use version_info::VersionInfo;
