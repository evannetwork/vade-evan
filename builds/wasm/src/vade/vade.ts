import { VadeApiSubstrate } from './vade-api-substrate';
import { VadeApiCl } from './vade-api-cl';
import { VadeApiBbs } from './vade-api-bbs';

class Vade {
  public did: VadeApiSubstrate;

  public cl: VadeApiCl;

  public bbs: VadeApiBbs;

  constructor(
    options?:
    { logLevel?: string, signer?: string, substrate?: string },
  ) {
    // config handling here
    this.did = new VadeApiSubstrate(options);
    this.cl = new VadeApiCl(options);
    this.bbs = new VadeApiBbs(options);
  }
}

export {
  Vade,
};
