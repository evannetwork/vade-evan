use jni::objects::{JClass, JObjectArray, JString};
use jni::sys::jstring;
use jni::JNIEnv;

// This keeps Rust from "mangling" the name and making it unique for this
// crate.
#[no_mangle]
pub extern "system" fn Java_com_vade_evan_Vade_ExecuteVade(
    env: JNIEnv,
    class: JClass,
    func_name: JString,
    arguments: JObjectArray,
    options: JString,
    config: JString,
) -> jstring {

    let output = env.new_string(format!("Hello, {}!", input))
    .expect("Couldn't create java string!");
    output.into_inner()
}
