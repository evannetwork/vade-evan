import { VadeApiSubstrate } from './vade-api-substrate';
import { VadeApiSidetree } from './vade-api-sidetree';
import { VadeApiBbs } from './vade-api-bbs';

class Vade {
  public did: VadeApiSubstrate;

  public bbs: VadeApiBbs;

  public sdid: VadeApiSidetree;

  constructor(
    options?:
    { logLevel?: string, signer?: string, substrate?: string },
  ) {
    // config handling here
    this.did = new VadeApiSubstrate(options);
    this.bbs = new VadeApiBbs(options);
    this.sdid = new VadeApiSidetree(options);
  }
}

export {
  Vade,
};
