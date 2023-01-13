static BUILD_INFO: &'static str = include_str!(concat!(env!("OUT_DIR"), "/build_info.txt"));

pub struct VersionInfo {}

impl VersionInfo {
    pub fn get_version_info() -> String {
        BUILD_INFO.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::VersionInfo;

    #[test]
    fn can_get_version_info() {
        let version_info = VersionInfo::get_version_info();

        assert!(version_info.contains("vade-evan"));
    }
}
