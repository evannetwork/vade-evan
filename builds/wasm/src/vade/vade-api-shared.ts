/* eslint-disable global-require */
/* eslint-disable import/no-extraneous-dependencies */
import * as wasm from './wasm';

// polyfill for  running in node environment
if (!global.Window) {
  const fetch = require('node-fetch');
  const ws = require('ws');
  global.Headers = fetch.Headers;
  global.Request = fetch.Request;
  global.Response = fetch.Response;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  global.Window = Object as any;
  global.fetch = fetch;
  global.WebSocket = ws;
}

wasm.set_panic_hook();

type VadeFunction =
  'did_resolve' |
  'did_update' |
  'did_create' |
  'run_custom_function' |
  'vc_zkp_create_credential_definition' |
  'vc_zkp_create_credential_offer' |
  'vc_zkp_create_credential_proposal' |
  'vc_zkp_create_credential_schema' |
  'vc_zkp_create_revocation_registry_definition' |
  'vc_zkp_finish_credential' |
  'vc_zkp_issue_credential' |
  'vc_zkp_present_proof' |
  'vc_zkp_request_credential' |
  'vc_zkp_request_proof' |
  'vc_zkp_revoke_credential' |
  'vc_zkp_verify_proof'
;

interface VadeOptions {
  identity: string;
  privateKey: string;
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
      customFunction,
      method,
      did,
      options,
      payload,
    }: {
      command: VadeFunction;
      customFunction?: string;
      method?: string;
      did?: string;
      options?: O;
      payload?: P;
    },
  ): Promise<R> {
    if (!command) {
      throw new Error('command missing');
    }
    if (!wasm[command]) {
      throw new Error(`unknown vade command: ${command}`);
    }
    if (!method && !did && command !== 'run_custom_function') {
      throw new Error('neither `did` nor `method` provided');
    }
    const config = {
      signer: this.signer,
      target: this.substrate,
    };

    const vadeArguments: unknown[] = [method || did];
    if (command === 'run_custom_function') {
      // only run_custom_function has an extra argument here
      vadeArguments.push(customFunction);
    }
    if (command !== 'did_resolve') {
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
    const wasmResult = await wasm[command].call(wasm, ...vadeArguments);
    try {
      return wasmResult
        ? JSON.parse(wasmResult)
        : null;
    } catch (ex) {
      throw new Error(`could not parse result for "${command}", wasm result: ${wasmResult}; ${ex.message || ex}`);
    }
  }
}

export {
  checkRequiredProperties,
  VadeOptions,
  VadeApiShared,
};
