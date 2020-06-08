use super::rpc_messages::{ResultE,OnMessageFn};

#[cfg(not(target_arch = "wasm32"))]
use ws::connect;
#[cfg(not(target_arch = "wasm32"))]
use ws::{CloseCode,Handler, Result,Message,Sender,Handshake};
#[cfg(not(target_arch = "wasm32"))]
use std::thread;


use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
use web_sys::{MessageEvent, WebSocket,ErrorEvent};
use futures::channel::mpsc::{
  Receiver,
  Sender as mpsc_Sender,
  channel
};

#[cfg(not(target_arch = "wasm32"))]
pub struct RpcClient {
  pub out: Sender,
  pub request: String,
  pub result: mpsc_Sender<String>,
  pub on_message_fn: OnMessageFn,
}
#[cfg(not(target_arch = "wasm32"))]
impl Handler for RpcClient {
  fn on_open(&mut self,_: Handshake ) -> Result<()> {
      debug!("sending message: {:?}", self.request.clone());
      self.out.send(self.request.clone()).unwrap();
      Ok(())
  }

  fn on_message(&mut self, msg: Message) -> Result<()> {
      let msgg = msg.as_text().unwrap();
      debug!("got msgg  not wasm message: {:?}", msgg);
      let res_e = (self.on_message_fn)(&msgg);
      match res_e {
        ResultE::None=>{},
        ResultE::Close=>{
          self.out.close(CloseCode::Normal).unwrap();
        },
        ResultE::S(s)=>{
          debug!("got result message: {:?}", s);
          self.result.try_send(s);
        },
        ResultE::SClose(s)=>{
          debug!("got result close message: {:?}", s);
          self.result.try_send(s);
          self.out.close(CloseCode::Normal).unwrap();
        }
      }
      Ok(())
  }
}
#[cfg(not(target_arch = "wasm32"))]
pub fn start_rpc_client_thread_sender(
  url: String,
  jsonreq: String,
  result_in: mpsc_Sender<String>,
  on_message_fn: OnMessageFn,
) {
  debug!("start send message: {:?}", jsonreq);
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
pub fn start_rpc_client_thread_sender(
    url: String,
    jsonreq: String,
    result_in: mpsc_Sender<String>,
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
          debug!("{}",&msgg);
          let res_e = (on_message_fn)(&msgg);
          debug!("SENDER got res_e");
          match res_e {
            ResultE::None=>{
              debug!("none");
            },
            ResultE::Close=>{
              debug!("close");
              ws_c.close_with_code(1000).unwrap();
            },
            ResultE::S(s)=>{
              debug!("SENDER s {}",&s);
              result_in.clone().try_send(s);
            },
            ResultE::SClose(s)=>{
              debug!("SENDER sclose");
              result_in.clone().try_send(s);
              ws_c.close_with_code(1000).unwrap();
            }
          }
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