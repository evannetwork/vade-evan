#[cfg(feature = "plugin-vc-zkp-bbs")]
mod credential_merge_with_pr33_later_on;
mod version_info;

#[cfg(feature = "plugin-vc-zkp-bbs")]
pub(crate) use credential_merge_with_pr33_later_on::Credential;
pub(crate) use version_info::VersionInfo;
