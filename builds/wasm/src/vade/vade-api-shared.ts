/* eslint-disable global-require */
/* eslint-disable import/no-extraneous-dependencies */
import * as wasm from './wasm';

// polyfill for  running in node environment
if (!global.Window) {
  const fetch = require('node-fetch');
  const ws = require('ws');
  const { LocalStorage } = require('node-localstorage');
  global.Headers = fetch.Headers;
  global.Request = fetch.Request;
  global.Response = fetch.Response;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  global.Window = Object as any;
  global.fetch = fetch;
  global.WebSocket = ws;
  global.localStorage = new LocalStorage('.local-storage');
}

wasm.set_panic_hook();

interface VadeOptions {
  identity: string;
  remoteSignerUrl?: string;
  signingKey: string;
}

/**
 * Checks for required properties within an object and throws an Error if one property is missing.
 *
 * @param toCheck object to check for required properties
 * @param requiredProperties list of string properties that should be included
 * @param type type of call
 *
 * @return     {true}  true if no error, throws if something is missing
 */
function checkRequiredProperties(
  toCheck: unknown,
  requiredProperties: string[],
  type: string,
): boolean {
  for (let i = 0; i < requiredProperties.length; i += 1) {
    if (!toCheck[requiredProperties[i]]) {
      throw new Error(`Parameter ${requiredProperties[i]} is required in ${type}!`);
    }
  }

  return true;
}

const DEFAULT_SIGNER = 'remote|http://localhost:7070/key/sign';

class VadeApiShared {
  private signer: string;

  private substrate: string;

  constructor(
    options?:
    { logLevel?: string, signer?: string, substrate?: string },
  ) {
    this.signer = options?.signer || DEFAULT_SIGNER;
    this.substrate = options?.substrate;
    if (options?.logLevel) {
      wasm.set_log_level(options.logLevel);
    }
  }

  public async executeVade<O, P, R>(
    {
      command,
      subcommand,
      method = 'did:evan',
      options,
      payload,
      did,
      signer = this.signer,
    }: {
      command: string;
      subcommand: string;
      method?: string;
      options?: O;
      payload?: P;
      did?: string;
      signer?: string;
    },
  ): Promise<R> {
    const cmd = `${command}_${subcommand}`;

    if (!command) {
      throw new Error('command missing');
    }
    if (!wasm[cmd]) {
      throw new Error(`unknown vade command: ${cmd}`);
    }
    if (!method && !did && command !== 'run_custom_function') {
      throw new Error('neither `did` nor `method` provided');
    }

    const config = {
      signer,
      target: this.substrate,
    };

    const vadeArguments: unknown[] = [method || did];
    if (command === 'run_custom_function') {
      // only run_custom_function has an extra argument here
      vadeArguments.push(subcommand);
    }
    if (cmd !== 'did_resolve') {
      // only did_resolve omits options and payload
      vadeArguments.push(
        options ? JSON.stringify(options) : '',
        payload? JSON.stringify(payload) : '',
      );
    }
    vadeArguments.push(config);

    if (vadeArguments.find((a) => typeof a === 'undefined')) {
      throw new Error(`invalid arguments for vade: ${JSON.stringify(vadeArguments)}`);
    }
    const wasmResult = await wasm[cmd].call(wasm, ...vadeArguments);
    try {
      return wasmResult
        ? JSON.parse(wasmResult)
        : null;
    } catch (ex) {
      throw new Error(`could not parse result for "${cmd}", wasm result: ${wasmResult}; ${ex.message || ex}`);
    }
  }
}

export {
  checkRequiredProperties,
  VadeOptions,
  VadeApiShared,
};
