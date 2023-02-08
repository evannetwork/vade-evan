const { Vade } = require('@equs/vade-wasm');

(async () => {
  const vade = new Vade({ signer: 'local' });

  // first create a did with sidetree and also generate the keys
  const did = await vade.did.createDid();
  console.log(did);


  // then add a new service endpoint to the did
  await vade.did.updateDid(did.did.didDocument.id,
    did.updateKey, {
    ...did.updateKey,
    nonce: '10'
  }, [
    {
      action: 'add-services',
      services: [{ 'id': 'sds', 'type': 'SecureDataStore', 'serviceEndpoint': 'https://w3id.org/did-resolution/v1' }]
    }
  ]);
  didDocument = await vade.did.getDid(did.did.didDocument.id);
  console.dir(didDocument);
})();
