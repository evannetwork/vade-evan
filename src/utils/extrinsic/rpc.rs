use super::rpc_messages::{ResultE,OnMessageFn};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, WebSocket,ErrorEvent};
use futures::channel::mpsc::{
  Receiver,
  Sender,
  channel
};

macro_rules! console_log {
  ($($t:tt)*) => (web_sys::console::log_1(&format_args!($($t)*).to_string().into()))
}

pub fn start_rpc_client_thread_sender(
    url: String,
    jsonreq: String,
    result_in: Sender<String>,
    on_message_fn: OnMessageFn,
  ) {
    let ws = WebSocket::new(&url).unwrap();
    let ws_c = ws.clone();
    console_log!("open websocket");
    let on_message = {
      Closure::wrap(Box::new(move |evt: MessageEvent| {
          let msgg = evt.data()
                      .as_string()
          .expect("Can't convert received data to a string");
          console_log!("{}",&msgg);
          let res_e = (on_message_fn)(&msgg);
          console_log!("SENDER got res_e");
          match res_e {
            ResultE::None=>{
              console_log!("none");
            },
            ResultE::Close=>{
              console_log!("close");
              ws_c.close_with_code(1000).unwrap();
            },
            ResultE::S(s)=>{
              console_log!("SENDER s {}",&s);
              result_in.clone().try_send(s);
            },
            ResultE::SClose(s)=>{
              console_log!("SENDER sclose");
              result_in.clone().try_send(s);
              ws_c.close_with_code(1000).unwrap();
            }
          }
      }) as Box<dyn FnMut(MessageEvent)>)
    };
    
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();
    let onerror_callback = Closure::wrap(Box::new(move |e: ErrorEvent| {
        console_log!("error event: {:?}", e);
    }) as Box<dyn FnMut(ErrorEvent)>);
    ws.set_onerror(Some(onerror_callback.as_ref().unchecked_ref()));
    onerror_callback.forget();
    let cloned_ws = ws.clone();
    let onopen_callback = Closure::wrap(Box::new(move |_| {
        match cloned_ws.send_with_str(&jsonreq) {
            Ok(_) => console_log!("message successfully sent"),
            Err(err) => console_log!("error sending message: {:?}", err),
        }
    }) as Box<dyn FnMut(JsValue)>);
    ws.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
    onopen_callback.forget();
  
  }