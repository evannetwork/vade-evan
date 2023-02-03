mod version_info;

#[cfg(feature = "plugin-vc-zkp-bbs")]
mod credential;
#[cfg(feature = "plugin-vc-zkp-bbs")]
mod credential_merge_with_pr33_later_on;

#[cfg(feature = "plugin-vc-zkp-bbs")]
pub(crate) use credential::Credential;
pub(crate) use version_info::VersionInfo;
