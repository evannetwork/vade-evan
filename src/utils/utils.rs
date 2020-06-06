#[cfg(not(target_arch = "wasm32"))]
use chrono::Utc;
use uuid::Uuid;

pub fn get_now_as_iso_string() -> String {
  #[cfg(target_arch = "wasm32")]
  return js_sys::Date::new_0().to_iso_string().to_string().into();
  #[cfg(not(target_arch = "wasm32"))]
  return Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string();
}

pub fn generate_uuid() -> String {
  return format!("{}", Uuid::new_v4());
}
