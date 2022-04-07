const { Vade } = require('@equs/vade-wasm');

const REMOTE_ISSUER_DID = 'did:evan:testcore:0x3fd50CC762DC91F5440B8a530Db7B52813730596'.toLocaleLowerCase();
const REMOTE_SIGNING_KEY = '270f69319fb71423d5f66f2a9d5f828536fa3c6108807449d4a541911b566b68';
const TYPE_SUBSTRATE = 'substrate';
const REMOTE_SIGNING_OPTIONS = {
  privateKey: REMOTE_SIGNING_KEY,
  identity: REMOTE_ISSUER_DID,
  type: TYPE_SUBSTRATE,
};

(async () => {
  try {
    const vade = new Vade({ signer: 'local' });

    const did = await vade.did.createDid(REMOTE_SIGNING_OPTIONS);
    console.log(did);

    await vade.did.updateDid(did, { didDocument: { foo: 'bar' } }, REMOTE_SIGNING_OPTIONS);
    didDocument = await vade.did.getDid(did);
    console.dir(didDocument);

    await vade.did.updateDid(
      did,
      { didDocument: { foo: 'bar', version: 2 } },
      REMOTE_SIGNING_OPTIONS,
    );
    didDocument = await vade.did.getDid(did);
    console.dir(didDocument);
  } catch (e) {
    console.error(`vade DID example run failed; ${e.message || e}${e.stack ? ` ${e.stack}` : ''}`);
  }
})();