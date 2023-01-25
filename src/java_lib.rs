use crate::c_lib::execute_vade;
use jni::objects::{JClass, JString};
use jni::sys::{jarray, jstring};
use jni::JNIEnv;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
pub extern "system" fn Java_com_vade_evan_Vade_executeVade(
    env: JNIEnv,
    _class: JClass,
    func_name: JString,
    arguments: jarray,
    options: JString,
    config: JString,
) -> jstring {
    let empty_owned_string = CString::new("").expect("CString::new failed");

    let mut c_str_func_name = empty_owned_string.as_ptr();
    if !func_name.is_null() {
        c_str_func_name = env
            .get_string_utf_chars(func_name)
            .expect("Couldn't get char array from func_name");
    }

    let mut c_str_options = empty_owned_string.as_ptr();
    if !options.is_null() {
        c_str_options = env
            .get_string_utf_chars(options)
            .expect("Couldn't get char array options");
    }

    let mut c_str_config = empty_owned_string.as_ptr();
    if !config.is_null() {
        c_str_config = env
            .get_string_utf_chars(config)
            .expect("Couldn't get char array config");
    }

    let mut arguments_vec: Vec<*const c_char> = Vec::new();
    let arg_count = env
        .get_array_length(arguments)
        .expect("Couldn't get arguments array length");

    for i in 0..arg_count {
        let array_element = env
            .get_object_array_element(arguments, i)
            .expect("Couldn't get array element");
        let array_element_string = JString::from(array_element);
        let arg = env
            .get_string_utf_chars(array_element_string)
            .expect("Couldn't get char array");
        arguments_vec.push(arg);
    }

    let result = execute_vade(
        c_str_func_name,
        arguments_vec.as_ptr(),
        arg_count as usize,
        c_str_options,
        c_str_config,
    );

    let result = unsafe { CStr::from_ptr(result).to_string_lossy().into_owned() };

    let output = env
        .new_string(result)
        .expect("Couldn't create java string from result!");

    output.into_inner()
}
