import { VadeApiSidetree } from './vade-api-sidetree';
import { VadeApiBbs } from './vade-api-bbs';

class Vade {
  public bbs: VadeApiBbs;

  public did: VadeApiSidetree;

  constructor(
    options?:
    { logLevel?: string, signer?: string },
  ) {
    // config handling here
    this.bbs = new VadeApiBbs(options);
    this.did = new VadeApiSidetree(options);
  }
}

export {
  Vade,
};
