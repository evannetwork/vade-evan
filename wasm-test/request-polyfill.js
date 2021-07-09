const fetch = require('node-fetch');
const ws = require('ws');
const os = require('os');

const platform = os.platform();
global.Headers = fetch.Headers;
global.Request = fetch.Request;
global.Response = fetch.Response;
global.Window = Object;
global.fetch = fetch;
global.WebSocket = ws;
