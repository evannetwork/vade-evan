use chrono::Utc;
use uuid::Uuid;

pub fn get_now_as_iso_string() -> String {
  return Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string();
}

pub fn generate_uuid() -> String {
  return format!("{}", Uuid::new_v4());
}
