/*
   Copyright 2019 Supercomputing Systems AG

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

pub enum ResultE {
    None,
    Close,
    S(String),
    SClose(String), //send and close
}

#[derive(Debug, PartialEq)]
pub enum XtStatus {
    Finalized,
    InBlock,
    Broadcast,
    Ready,
    Future,
    Error,
    Unknown,
}

pub type OnMessageFn = fn(msg: &str) -> ResultE;
/*macro_rules! debug {
    ($($t:tt)*) => (web_sys::console::log_1(&format_args!($($t)*).to_string().into()))
}
macro_rules! error {
    ($($t:tt)*) => (web_sys::console::log_1(&format_args!($($t)*).to_string().into()))
}
macro_rules! warn {
    ($($t:tt)*) => (web_sys::console::log_1(&format_args!($($t)*).to_string().into()))
}
macro_rules! info {
    ($($t:tt)*) => (web_sys::console::log_1(&format_args!($($t)*).to_string().into()))
}*/
pub fn on_get_request_msg(msg: &str) -> ResultE {
    let value: serde_json::Value = serde_json::from_str(msg).unwrap();
    ResultE::SClose(value["result"].to_string())
}

pub fn on_subscription_msg(msg: &str) -> ResultE {
    let value: serde_json::Value = serde_json::from_str(msg).unwrap();
    match value["id"].as_str() {
        Some(_idstr) => ResultE::None,
        _ => {
            // subscriptions
            debug!("no id field found in response. must be subscription");
            debug!("method: {:?}", value["method"].as_str());
            match value["method"].as_str() {
                Some("state_storage") => {
                    let _changes = &value["params"]["result"]["changes"];
                    let _res_str = _changes[0][1].as_str().unwrap().to_string();
                    ResultE::S(_res_str)
                }
                _ => {
                    error!("unsupported method");
                    ResultE::None
                }
            }
        }
    }
}

pub fn on_extrinsic_msg_until_finalized(msg: &str) -> ResultE {
    debug!("got msg {}", msg);
    match parse_status(msg) {
        (XtStatus::Finalized, val) => end_process(val),
        (XtStatus::Error, e) => end_process(e),
        (XtStatus::Future, _) => {
            warn!("extrinsic has 'future' status. aborting");
            end_process(None)
        }
        _ => ResultE::None,
    }
}

pub fn on_extrinsic_msg_until_in_block(msg: &str) -> ResultE {
    debug!("got msg {}", msg);
    match parse_status(msg) {
        (XtStatus::Finalized, val) => end_process(val),
        (XtStatus::InBlock, val) => end_process(val),
        (XtStatus::Future, _) => end_process(None),
        (XtStatus::Error, _) => end_process(None),
        _ => ResultE::None,
    }
}

pub fn on_extrinsic_msg_until_broadcast(msg: &str) -> ResultE {
    debug!("got msg {}", msg);
    match parse_status(msg) {
        (XtStatus::Finalized, val) => end_process(val),
        (XtStatus::Broadcast, _) => end_process(None),
        (XtStatus::Future, _) => end_process(None),
        (XtStatus::Error, _) => end_process(None),
        _ => ResultE::None,
    }
}

pub fn on_extrinsic_msg_until_ready(msg: &str) -> ResultE {
    debug!("got msg {}", msg);
    match parse_status(msg) {
        (XtStatus::Finalized, val) => end_process(val),
        (XtStatus::Ready, _) => end_process(None),
        (XtStatus::Future, _) => end_process(None),
        (XtStatus::Error, e) => end_process(e),
        _ => ResultE::None,
    }
}

fn end_process(value: Option<String>) -> ResultE {
    // return result to calling thread
    debug!("Thread end value:{:?}", value);
    let val = value.unwrap_or_else(|| "".to_string());
    ResultE::SClose(val)
}

fn parse_status(msg: &str) -> (XtStatus, Option<String>) {
    let value: serde_json::Value = serde_json::from_str(msg).unwrap();
    match value["error"].as_object() {
        Some(obj) => {
            let error_message = obj.get("message").unwrap().as_str().unwrap().to_owned();
            error!(
                "extrinsic error code {}: {}",
                obj.get("code").unwrap().as_u64().unwrap(),
                error_message
            );
            (XtStatus::Error, Some(error_message))
        }
        None => match value["params"]["result"].as_object() {
            Some(obj) => {
                if let Some(hash) = obj.get("finalized") {
                    info!("finalized: {:?}", hash);
                    (XtStatus::Finalized, Some(hash.to_string()))
                } else if let Some(hash) = obj.get("inBlock") {
                    info!("inBlock: {:?}", hash);
                    (XtStatus::InBlock, Some(hash.to_string()))
                } else if let Some(array) = obj.get("broadcast") {
                    info!("broadcast: {:?}", array);
                    (XtStatus::Broadcast, Some(array.to_string()))
                } else {
                    (XtStatus::Unknown, None)
                }
            }
            None => match value["params"]["result"].as_str() {
                Some("ready") => (XtStatus::Ready, None),
                Some("future") => (XtStatus::Future, None),
                Some(&_) => (XtStatus::Unknown, None),
                None => (XtStatus::Unknown, None),
            },
        },
    }
}
