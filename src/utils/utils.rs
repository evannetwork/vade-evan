use chrono::Utc;

pub fn get_now_as_iso_string() -> String {
  return Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string();
}
