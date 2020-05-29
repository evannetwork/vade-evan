pub enum ResultE{
    None,
    Close,
    S(String),
    SClose(String) //send and close
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
        Some(_idstr) => {
            ResultE::None
        }
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
                _ => {error!("unsupported method");ResultE::None},
            }
        }
    }
}

pub fn on_extrinsic_msg(msg: &str) -> ResultE{
    let value: serde_json::Value = serde_json::from_str(msg).unwrap();
    match value["id"].as_str() {
        Some(idstr) => match idstr.parse::<u32>() {
            Ok(req_id) => match req_id {
                REQUEST_TRANSFER => match value.get("error") {
                    Some(err) => {error!("ERROR: {:?}", err);ResultE::None},
                    _ => {debug!("no error");ResultE::None},
                },
                _ => {debug!("Unknown request id");ResultE::None},
            },
            Err(_) => {error!("error assigning request id");ResultE::None},
        },
        _ => {
            // subscriptions
            debug!("no id field found in response. must be subscription");
            debug!("method: {:?}", value["method"].as_str());
            match value["method"].as_str() {
                Some("author_extrinsicUpdate") => {
                    match value["params"]["result"].as_str() {
                        Some(res) => {debug!("author_extrinsicUpdate: {}", res);ResultE::None},
                        _ => {
                            debug!(
                                "author_extrinsicUpdate: finalized: {}",
                                value["params"]["result"]["finalized"].as_str().unwrap()
                            );
                            // return result to calling thread
                            ResultE::SClose(value["params"]["result"]["finalized"]
                                        .as_str()
                                        .unwrap()
                                        .to_string())
                        }
                    }
                }
                _ => {error!("unsupported method");ResultE::None},
            }
        }
    }
}

pub fn on_extrinsic_msg_until_finalized(
    msg: &str
) -> ResultE {
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

pub fn on_extrinsic_msg_until_in_block(
    msg: &str
) -> ResultE {
    debug!("got msg {}", msg);
    match parse_status(msg) {
        (XtStatus::Finalized, val) => end_process(val),
        (XtStatus::InBlock, val) => end_process(val),
        (XtStatus::Future, _) => end_process(None),
        (XtStatus::Error, _) => end_process(None),
        _ => ResultE::None,
    }
}

pub fn on_extrinsic_msg_until_broadcast(
    msg: &str
) -> ResultE {
    debug!("got msg {}", msg);
    match parse_status(msg) {
        (XtStatus::Finalized, val) => end_process(val),
        (XtStatus::Broadcast, _) => end_process(None),
        (XtStatus::Future, _) => end_process(None),
        (XtStatus::Error, _) => end_process(None),
        _ => ResultE::None,
    }
}

pub fn on_extrinsic_msg_until_ready(
    msg: &str
) -> ResultE {
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

