#[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
mod credential;
mod datatypes;
#[cfg(feature = "plugin-did-sidetree")]
mod did;
#[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
mod presentation;
#[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
mod shared;
mod version_info;

#[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
pub(crate) use credential::{Credential, CredentialError};
#[cfg(feature = "plugin-did-sidetree")]
pub(crate) use did::Did;
#[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
pub(crate) use presentation::{Presentation, PresentationError};
pub(crate) use version_info::VersionInfo;
