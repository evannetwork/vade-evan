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

use futures::channel::mpsc::Sender as ThreadOut;
use log::{debug, error, info, warn};
#[cfg(not(target_arch = "wasm32"))]
use ws::{CloseCode, Handler, Handshake, Message, Result, Sender};

#[cfg(target_arch = "wasm32")]
use web_sys::WebSocket;

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

#[cfg(not(target_arch = "wasm32"))]
pub type OnMessageFn = fn(msg: Message, out: Sender, result: ThreadOut<String>) -> Result<()>;

#[cfg(target_arch = "wasm32")]
pub type OnMessageFn = fn(
    msg: &str,
    out: &WebSocket,
    result: ThreadOut<String>,
) -> Result<(), Box<dyn std::error::Error>>;

#[cfg(not(target_arch = "wasm32"))]
pub struct RpcClient {
    pub out: Sender,
    pub request: String,
    pub result: ThreadOut<String>,
    pub on_message_fn: OnMessageFn,
}
#[cfg(not(target_arch = "wasm32"))]
impl Handler for RpcClient {
    fn on_open(&mut self, _: Handshake) -> Result<()> {
        info!("sending request: {}", self.request);
        self.out.send(self.request.clone()).unwrap();
        Ok(())
    }

    fn on_message(&mut self, msg: Message) -> Result<()> {
        (self.on_message_fn)(msg, self.out.clone(), self.result.clone())
    }
}
#[cfg(not(target_arch = "wasm32"))]
pub fn on_get_request_msg(msg: Message, out: Sender, result: ThreadOut<String>) -> Result<()> {
    info!("Got get_request_msg {}", msg);
    let retstr = msg.as_text().unwrap();
    let value: serde_json::Value = serde_json::from_str(retstr).unwrap();

    result
        .clone()
        .try_send(value["result"].to_string())
        .unwrap();
    out.close(CloseCode::Normal).unwrap();
    Ok(())
}
#[cfg(not(target_arch = "wasm32"))]
pub fn on_subscription_msg(msg: Message, _out: Sender, result: ThreadOut<String>) -> Result<()> {
    info!("got on_subscription_msg {}", msg);
    let retstr = msg.as_text().unwrap();
    let value: serde_json::Value = serde_json::from_str(retstr).unwrap();
    match value["id"].as_str() {
        Some(_idstr) => {}
        _ => {
            // subscriptions
            debug!("no id field found in response. must be subscription");
            debug!("method: {:?}", value["method"].as_str());
            debug!("retstr: {:?}", retstr);
            match value["method"].as_str() {
                Some("state_storage") => {
                    let changes = &value["params"]["result"]["changes"];

                    match changes[0][1].as_str() {
                        Some(change_set) => {
                            result
                                .clone()
                                .try_send(change_set.to_owned())
                                .unwrap_or_else(|_| {
                                    _out.close(CloseCode::Normal).unwrap();
                                });
                        }
                        None => println!("No events happened"),
                    };
                }
                Some("chain_finalizedHead") => {
                    serde_json::to_string(&value["params"]["result"])
                        .map(|head| {
                            result.clone().try_send(head).unwrap_or_else(|_| {
                                _out.close(CloseCode::Normal).unwrap();
                            });
                        })
                        .unwrap_or_else(|_| error!("Could not parse header"));
                }
                _ => error!("unsupported method"),
            }
        }
    };
    Ok(())
}
#[cfg(not(target_arch = "wasm32"))]
pub fn on_extrinsic_msg_until_finalized(
    msg: Message,
    out: Sender,
    result: ThreadOut<String>,
) -> Result<()> {
    let retstr = msg.as_text().unwrap();
    debug!("got msg {}", retstr);
    match parse_status(retstr) {
        (XtStatus::Finalized, val) => end_process(out, result, val),
        (XtStatus::Error, e) => end_process(out, result, e),
        (XtStatus::Future, _) => {
            warn!("extrinsic has 'future' status. aborting");
            end_process(out, result, None);
        }
        _ => (),
    };
    Ok(())
}
#[cfg(not(target_arch = "wasm32"))]
pub fn on_extrinsic_msg_until_in_block(
    msg: Message,
    out: Sender,
    result: ThreadOut<String>,
) -> Result<()> {
    let retstr = msg.as_text().unwrap();
    debug!("got msg {}", retstr);
    match parse_status(retstr) {
        (XtStatus::Finalized, val) => end_process(out, result, val),
        (XtStatus::InBlock, val) => end_process(out, result, val),
        (XtStatus::Future, _) => end_process(out, result, None),
        (XtStatus::Error, _) => end_process(out, result, None),
        _ => (),
    };
    Ok(())
}
#[cfg(not(target_arch = "wasm32"))]
pub fn on_extrinsic_msg_until_broadcast(
    msg: Message,
    out: Sender,
    result: ThreadOut<String>,
) -> Result<()> {
    let retstr = msg.as_text().unwrap();
    debug!("got msg {}", retstr);
    match parse_status(retstr) {
        (XtStatus::Finalized, val) => end_process(out, result, val),
        (XtStatus::Broadcast, _) => end_process(out, result, None),
        (XtStatus::Future, _) => end_process(out, result, None),
        (XtStatus::Error, _) => end_process(out, result, None),
        _ => (),
    };
    Ok(())
}
#[cfg(not(target_arch = "wasm32"))]
pub fn on_extrinsic_msg_until_ready(
    msg: Message,
    out: Sender,
    result: ThreadOut<String>,
) -> Result<()> {
    let retstr = msg.as_text().unwrap();
    debug!("got msg {}", retstr);
    match parse_status(retstr) {
        (XtStatus::Finalized, val) => end_process(out, result, val),
        (XtStatus::Ready, _) => end_process(out, result, None),
        (XtStatus::Future, _) => end_process(out, result, None),
        (XtStatus::Error, e) => end_process(out, result, e),
        _ => (),
    };
    Ok(())
}
#[cfg(not(target_arch = "wasm32"))]
fn end_process(out: Sender, result: ThreadOut<String>, value: Option<String>) {
    // return result to calling thread
    debug!("Thread end result :{:?} value:{:?}", result, value);
    let val = value.unwrap_or_else(|| "".to_string());
    result.clone().try_send(val).unwrap();
    out.close(CloseCode::Normal).unwrap();
}

// WASM implementation

#[cfg(target_arch = "wasm32")]
pub fn on_get_request_msg(
    msg: &str,
    out: &WebSocket,
    result: ThreadOut<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Got get_request_msg {}", msg);
    let value: serde_json::Value = serde_json::from_str(msg).unwrap();

    result
        .clone()
        .try_send(value["result"].to_string())
        .unwrap();
    out.close_with_code(1000).unwrap();
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub fn on_subscription_msg(
    msg: &str,
    _out: &WebSocket,
    result: ThreadOut<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("got on_subscription_msg {}", msg);
    let value: serde_json::Value = serde_json::from_str(msg).unwrap();
    match value["id"].as_str() {
        Some(_idstr) => {}
        _ => {
            // subscriptions
            debug!("no id field found in response. must be subscription");
            debug!("method: {:?}", value["method"].as_str());
            match value["method"].as_str() {
                Some("state_storage") => {
                    let changes = &value["params"]["result"]["changes"];
                    match changes[0][1].as_str() {
                        Some(change_set) => {
                            let _ = result.clone().try_send(change_set.to_owned());
                        }
                        None => println!("No events happened"),
                    };
                }
                Some("chain_finalizedHead") => {
                    serde_json::to_string(&value["params"]["result"])
                        .map(|head| {
                            let _ = result.clone().try_send(head);
                        })
                        .unwrap_or_else(|_| error!("Could not parse header"));
                }
                _ => error!("unsupported method"),
            }
        }
    };
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub fn on_extrinsic_msg_until_finalized(
    msg: &str,
    out: &WebSocket,
    result: ThreadOut<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!("got msg {}", msg);
    match parse_status(msg) {
        (XtStatus::Finalized, val) => end_process(out, result, val),
        (XtStatus::Error, e) => end_process(out, result, e),
        (XtStatus::Future, _) => {
            warn!("extrinsic has 'future' status. aborting");
            end_process(out, result, None);
        }
        _ => (),
    };
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub fn on_extrinsic_msg_until_in_block(
    msg: &str,
    out: &WebSocket,
    result: ThreadOut<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!("got msg {}", msg);
    match parse_status(msg) {
        (XtStatus::Finalized, val) => end_process(out, result, val),
        (XtStatus::InBlock, val) => end_process(out, result, val),
        (XtStatus::Future, _) => end_process(out, result, None),
        (XtStatus::Error, _) => end_process(out, result, None),
        _ => (),
    };
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub fn on_extrinsic_msg_until_broadcast(
    msg: &str,
    out: &WebSocket,
    result: ThreadOut<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!("got msg {}", msg);
    match parse_status(msg) {
        (XtStatus::Finalized, val) => end_process(out, result, val),
        (XtStatus::Broadcast, _) => end_process(out, result, None),
        (XtStatus::Future, _) => end_process(out, result, None),
        (XtStatus::Error, _) => end_process(out, result, None),
        _ => (),
    };
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub fn on_extrinsic_msg_until_ready(
    msg: &str,
    out: &WebSocket,
    result: ThreadOut<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!("got msg {}", msg);
    match parse_status(msg) {
        (XtStatus::Finalized, val) => end_process(out, result, val),
        (XtStatus::Ready, _) => end_process(out, result, None),
        (XtStatus::Future, _) => end_process(out, result, None),
        (XtStatus::Error, e) => end_process(out, result, e),
        _ => (),
    };
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn end_process(out: &WebSocket, result: ThreadOut<String>, value: Option<String>) {
    // return result to calling thread
    debug!("Thread end result :{:?} value:{:?}", result, value);
    let val = value.unwrap_or_else(|| "".to_string());
    result.clone().try_send(val).unwrap();
    out.close_with_code(1000).unwrap();
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
