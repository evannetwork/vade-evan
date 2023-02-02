const { Vade } = require('@equs/vade-wasm');

const REMOTE_ISSUER_DID = 'did:evan:testcore:0x3fd50CC762DC91F5440B8a530Db7B52813730596'.toLocaleLowerCase();
const REMOTE_SIGNING_KEY = '270f69319fb71423d5f66f2a9d5f828536fa3c6108807449d4a541911b566b68';
const REMOTE_SIGNING_OPTIONS = {
  signingKey: REMOTE_SIGNING_KEY,
  identity: REMOTE_ISSUER_DID,
};

(async () => {
	const vade = new Vade({ signer: 'local' });

	const did = await vade.did.createDid(REMOTE_SIGNING_OPTIONS);
	console.log(did);

	await vade.did.updateDid(did, { didDocument: { foo: 'bar' } }, REMOTE_SIGNING_OPTIONS);
    didDocument = await vade.did.getDid(did);
	console.dir(didDocument);

	await vade.did.updateDid(did, { didDocument: { foo: 'bar', version: 2 } }, REMOTE_SIGNING_OPTIONS);
	didDocument = await vade.did.getDid(did);
	console.dir(didDocument);

	const sdid = await vade.sdid.createDid(null, null, null, null);
	sdidDocument = await vade.sdid.getDid(sdid.did.didDocument.id);
	console.dir(sdidDocument);

	await vade.sdid.updateDid(sdid, sdid.updateKey, {},
		[{"action":"add-service-endpoints",
			      "service_endpoints":
				  [{"id":"sds","type":"SecureDataStrore","endpoint":"https://w3id.org/did-resolution/v1"}]}]
	);
	sdidDocument = await vade.sdid.getDid(sdid.did.didDocument.id);
	console.dir(sdidDocument);
})();
