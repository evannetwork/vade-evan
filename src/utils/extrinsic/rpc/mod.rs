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
#[cfg(not(target_arch = "wasm32"))]
use std::thread;

#[cfg(target_arch = "wasm32")]
use web_sys::{MessageEvent, WebSocket,ErrorEvent};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

#[cfg(not(target_arch = "wasm32"))]
use ws::connect;

pub use client::XtStatus;
use client::*;

pub mod client;
pub mod json_req;

pub fn get(url: String, json_req: String, result_in: ThreadOut<String>) {
    start_rpc_client_thread(url, json_req, result_in, on_get_request_msg)
}

pub fn send_extrinsic(url: String, json_req: String, result_in: ThreadOut<String>) {
    start_rpc_client_thread(url, json_req, result_in, on_extrinsic_msg_until_ready)
}

pub fn send_extrinsic_and_wait_until_broadcast(
    url: String,
    json_req: String,
    result_in: ThreadOut<String>,
) {
    start_rpc_client_thread(url, json_req, result_in, on_extrinsic_msg_until_broadcast)
}

pub fn send_extrinsic_and_wait_until_in_block(
    url: String,
    json_req: String,
    result_in: ThreadOut<String>,
) {
    start_rpc_client_thread(url, json_req, result_in, on_extrinsic_msg_until_in_block)
}

pub fn send_extrinsic_and_wait_until_finalized(
    url: String,
    json_req: String,
    result_in: ThreadOut<String>,
) {
    start_rpc_client_thread(url, json_req, result_in, on_extrinsic_msg_until_finalized)
}

pub fn start_subcriber(url: String, json_req: String, result_in: ThreadOut<String>) {
    start_rpc_client_thread(url, json_req, result_in, on_subscription_msg)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn start_rpc_client_thread(
    url: String,
    jsonreq: String,
    result_in: ThreadOut<String>,
    on_message_fn: OnMessageFn,
) {
    let _client = thread::Builder::new()
        .name("client".to_owned())
        .spawn(move || {
            connect(url, |out| RpcClient {
                out,
                request: jsonreq.clone(),
                result: result_in.clone(),
                on_message_fn,
            })
            .unwrap()
        })
        .unwrap();
}


#[cfg(target_arch = "wasm32")]
pub fn start_rpc_client_thread(
    url: String,
    jsonreq: String,
    result_in: ThreadOut<String>,
    on_message_fn: OnMessageFn,
  ) {
    let ws = WebSocket::new(&url).unwrap();
    let ws_c = ws.clone();
    debug!("open websocket");
    let on_message = {
      Closure::wrap(Box::new(move |evt: MessageEvent| {
          let msgg = evt.data()
                      .as_string()
          .expect("Can't convert received data to a string");
          let _res_e = (on_message_fn)(&msgg, &ws_c, result_in.clone());
      }) as Box<dyn FnMut(MessageEvent)>)
    };
    
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();
    let onerror_callback = Closure::wrap(Box::new(move |e: ErrorEvent| {
        debug!("error event: {:?}", e);
    }) as Box<dyn FnMut(ErrorEvent)>);
    ws.set_onerror(Some(onerror_callback.as_ref().unchecked_ref()));
    onerror_callback.forget();
    let cloned_ws = ws.clone();
    let onopen_callback = Closure::wrap(Box::new(move |_| {
        debug!("sending message: {:?}", jsonreq);
        match cloned_ws.send_with_str(&jsonreq) {
            Ok(_) => debug!("message successfully sent"),
            Err(err) => debug!("error sending message: {:?}", err),
        }
    }) as Box<dyn FnMut(JsValue)>);
    ws.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
    onopen_callback.forget();
  
  }