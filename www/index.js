//import * as wasm from "vade-tnt";
const fetch = require('node-fetch')
const ws = require('ws')
global.Headers = fetch.Headers
global.Request = fetch.Request
global.Response = fetch.Response
global.Window = Object // lol
global.fetch = fetch
global.WebSocket = ws
const wasm = require('./vade_tnt.js');

/**
 * whitelists a specific evan did on substrate that this private key can create DIDs
 * @param {string} privateKey
 * @param {string} identity
 */
async function whitelistIdentity(privateKey, identity) {
  if(!identity.startsWith('did')) {
    throw new Error(`identity should start with did:evan:...`);
  }

  const splittedDid = identity.split(':');
  const plainDidId = splittedDid[splittedDid.length - 1];

  await wasm.whitelist_identity(privateKey, plainDidId);
}

/**
 * creates a schema on substrate and returns it
 * @param {object} params parameters for the schema
 * @param {string} params.name name of the schema
 * @param {string} params.description description of the schema
 * @param {object} params.properties properties attached to the schema
 * @param {object} params.properties.KEY KEY name of the property
 * @param {string} params.properties.KEY.type type of the property (string,...)
 * @param {array}  params.requiredProperties array of strings with required properties
 * @param {string} params.publicKeyDidId id string of the signed public key in did (e.g. did:evan:0x12345#key-1)
 * @param {string} params.privateKeyDidId associated private key for the did id
 * @param {object} options options for vade
 * @param {string} options.identity Substrate identity to use (e.g. did:evan:0x12345)
 * @param {string} options.privateKey private key used for creating dids (public-key must be listed in identity)
 */
async function createSchema(params, options) {

  if(options && options.identity && !options.identity.startsWith('did')) {
    throw new Error(`identity should start with did:evan:...`);
  }

  if(options && !options.privateKey) {
    throw new Error(`privateKey should be provided in options`);
  }

  if(params && !params.name) {
    throw new Error(`name must be provided in params`);
  }

  if(params && !params.properties) {
    throw new Error(`properties must be provided in params`);
  }

  if(params && !params.requiredProperties) {
    throw new Error(`requiredProperties must be provided in params`);
  }

  if(params && !params.publicKeyDidId) {
    throw new Error(`publicKeyDidId must be provided in params`);
  }

  if(params && !params.privateKeyDidId) {
    throw new Error(`privateKeyDidId must be provided in params`);
  }

  if(params && !params.identity) {
    throw new Error(`identity must be provided in params`);
  }
  const splittedDid = options.identity.split(':');
  const plainDidId = splittedDid[splittedDid.length - 1];
  const schema = await wasm.create_schema(
    params.identity,
    params.name,
    params.description || "",
    JSON.stringify(params.properties),
    JSON.stringify(params.requiredProperties),
    params.publicKeyDidId,
    params.privateKeyDidId,
    options.privateKey,
    plainDidId
  );

  return JSON.parse(schema);
}


/**
 * creates a credential definition on substrate and returns it
 * @param {object} params parameters for the schema
 * @param {string} params.schemaId id for the used schema
 * @param {string} params.issuerDid did for the issuer (e.g. did:evan:0x12345)
 * @param {string} params.publicKeyDidId id string of the signed public key in did (e.g. did:evan:0x12345#key-1)
 * @param {string} params.privateKeyDidId associated private key for the did id
 * @param {object} options options for vade
 * @param {string} options.identity Substrate identity to use (e.g. did:evan:0x12345)
 * @param {string} options.privateKey private key used for creating dids (public-key must be listed in identity)
 */
async function createCredentialDefinition(params, options) {

  if(options && options.identity && !options.identity.startsWith('did')) {
    throw new Error(`identity should start with did:evan:...`);
  }

  if(options && !options.privateKey) {
    throw new Error(`privateKey should be provided in options`);
  }

  if(params && !params.schemaId) {
    throw new Error(`schemaId must be provided in params`);
  }

  if(params && !params.publicKeyDidId) {
    throw new Error(`publicKeyDidId must be provided in params`);
  }

  if(params && !params.privateKeyDidId) {
    throw new Error(`privateKeyDidId must be provided in params`);
  }
  const splittedDid = options.identity.split(':');
  const plainDidId = splittedDid[splittedDid.length - 1];
  const credDef = await wasm.create_credential_definition(
    params.schemaId,
    params.issuerDid,
    params.publicKeyDidId,
    params.privateKeyDidId,
    options.privateKey,
    plainDidId
  );

  const parsedDef = JSON.parse(credDef);
  return {
    definition: parsedDef[0],
    definitionKey: parsedDef[1]
  };
}

/**
 * creates a master secret for issuing credentials and presenting proofs
 */
function createMasterSecret() {
  return JSON.parse(wasm.create_master_secret());
}


/**
 * creates a proof request from a given issuer and prover
 * @param {object} params parameters for the schema
 * @param {string} params.schemaId id for the used schema
 * @param {string} params.issuerDid did for the issuer (e.g. did:evan:0x12345)
 * @param {string} params.proverDid did for the prover (e.g. did:evan:0x12346)
 * @param {array}  params.revealedAttributes array of strings with to be revealed attributes from the schema
 */
async function requestProof(params) {

  if(params && !params.schemaId) {
    throw new Error(`schemaId must be provided in params`);
  }

  if(params && !params.issuerDid) {
    throw new Error(`issuerDid must be provided in params`);
  }

  if(params && !params.proverDid) {
    throw new Error(`proverDid must be provided in params`);
  }

  if(params && !params.revealedAttributes) {
    throw new Error(`revealedAttributes must be provided in params`);
  }

  const requestedProof = await wasm.request_proof(
    params.schemaId,
    params.issuerDid,
    params.proverDid,
    JSON.stringify(params.revealedAttributes)
  );

  return JSON.parse(requestedProof);
}

/**
 * creates a proposal for a credential for a given schema
 * @param {object} params parameters for the schema
 * @param {string} params.schemaId id for the used schema
 * @param {string} params.issuerDid did for the issuer (e.g. did:evan:0x12345)
 * @param {string} params.subjectDid did for the subject (e.g. did:evan:0x12346)
 */
async function createCredentialProposal(params) {

  if(params && !params.schemaId) {
    throw new Error(`schemaId must be provided in params`);
  }

  if(params && !params.issuerDid) {
    throw new Error(`issuerDid must be provided in params`);
  }

  if(params && !params.subjectDid) {
    throw new Error(`subjectDid must be provided in params`);
  }

  const proposal = await wasm.create_credential_proposal(
    params.schemaId,
    params.subjectDid,
    params.issuerDid
  );

  return JSON.parse(proposal);
}

/**
 * creates a offer for a credential for a given proposal
 * @param {object} params parameters for the offer
 * @param {string} params.proposal given credential proposal
 * @param {string} params.credentialDefinitionId id of the credential definition
 */
async function createCredentialOffer(params) {

  if(params && !params.proposal) {
    throw new Error(`proposal must be provided in params`);
  }

  if(params && !params.credentialDefinitionId) {
    throw new Error(`credentialDefinitionId must be provided in params`);
  }

  const offer = await wasm.create_credential_offer(
    JSON.stringify(params.proposal),
    params.credentialDefinitionId
  );

  return JSON.parse(offer);
}

/**
 * creates a request for a credential with given values
 * @param {object} params parameters for the request
 * @param {string} params.offer given credential offer
 * @param {string} params.credentialDefinition credential definition object
 * @param {string} params.masterSecret master secret object
 * @param {object} params.credentialValues object with values from the schema
 */
async function createCredentialRequest(params) {

  if(params && !params.offer) {
    throw new Error(`offer must be provided in params`);
  }

  if(params && !params.masterSecret) {
    throw new Error(`masterSecret must be provided in params`);
  }

  if(params && !params.credentialValues) {
    throw new Error(`credentialValues must be provided in params`);
  }

  const request = await wasm.create_credential_request(
    JSON.stringify(params.offer),
    JSON.stringify(params.masterSecret),
    JSON.stringify(params.credentialValues)
  );

  const parsedRequest = JSON.parse(request);
  return {
    request: parsedRequest[0],
    blindingFactors: parsedRequest[1]
  }
}

/**
 * creates a revocation registry for a given credential definiton
 * @param {object} params parameters for the revocation registry
 * @param {string} params.credentialDefinitionId credential definition object
 * @param {number} params.maxCredentialCount given credential offer
 * @param {string} params.publicKeyDidId id string of the signed public key in did (e.g. did:evan:0x12345#key-1)
 * @param {string} params.privateKeyDidId associated private key for the did id
 * @param {object} options options for vade
 * @param {string} options.identity Substrate identity to use (e.g. did:evan:0x12345)
 * @param {string} options.privateKey private key used for creating dids (public-key must be listed in identity)
 */
async function createRevocationRegistry(params, options) {

  if(options && options.identity && !options.identity.startsWith('did')) {
    throw new Error(`identity should start with did:evan:...`);
  }

  if(options && !options.privateKey) {
    throw new Error(`privateKey should be provided in options`);
  }


  if(params && !params.credentialDefinitionId) {
    throw new Error(`credentialDefinitionId must be provided in params`);
  }

  if(params && !params.maxCredentialCount) {
    throw new Error(`maxCredentialCount must be provided in params`);
  }

  if(params && !params.publicKeyDidId) {
    throw new Error(`publicKeyDidId must be provided in params`);
  }

  if(params && !params.privateKeyDidId) {
    throw new Error(`privateKeyDidId must be provided in params`);
  }

  const splittedDid = options.identity.split(':');
  const plainDidId = splittedDid[splittedDid.length - 1];
  const revocationRegistry = await wasm.create_revocation_registry_definition(
    params.credentialDefinitionId,
    params.maxCredentialCount,
    params.publicKeyDidId,
    params.privateKeyDidId,
    options.privateKey,
    plainDidId
  );

  return JSON.parse(revocationRegistry);
}

/**
 * issues a credential for a given definition for a given subject
 * @param {object} params parameters for the revocation registry
 * @param {object} params.credentialDefinition credential definition object
 * @param {object} params.credentialDefinitionKey credential definition key object
 * @param {object} params.credentialRequest credential request object
 * @param {object} params.revocationRegistryKey revocation registry key object
 * @param {object} params.revocationRegistryInfo revocation registry info object
 * @param {object} params.revocationRegistryDefinition revocation registry definition object
 * @param {object} params.blindingFactors blinding factors object
 * @param {object} params.masterSecret master secret object
 * @param {string} params.issuerDid did of the issuer (e.g. did:evan:0x12345)
 * @param {string} params.subjectDid did of the subject (e.g. did:evan:0x12346)
 */
async function issueCredential(params) {

  if(params && !params.credentialDefinition) {
    throw new Error(`credentialDefinition must be provided in params`);
  }

  if(params && !params.credentialDefinitionKey) {
    throw new Error(`credentialDefinitionKey must be provided in params`);
  }

  if(params && !params.credentialRequest) {
    throw new Error(`credentialRequest must be provided in params`);
  }

  if(params && !params.revocationRegistryKey) {
    throw new Error(`revocationRegistryKey must be provided in params`);
  }

  if(params && !params.revocationRegistryInfo) {
    throw new Error(`revocationRegistryInfo must be provided in params`);
  }

  if(params && !params.revocationRegistryDefinitionDid) {
    throw new Error(`revocationRegistryDefinitionDid must be provided in params`);
  }

  if(params && !params.blindingFactors) {
    throw new Error(`blindingFactors must be provided in params`);
  }

  if(params && !params.masterSecret) {
    throw new Error(`masterSecret must be provided in params`);
  }

  if(params && !params.issuerDid) {
    throw new Error(`issuerDid must be provided in params`);
  }

  if(params && !params.subjectDid) {
    throw new Error(`subjectDid must be provided in params`);
  }

  const credential = await wasm.issue_credential(
    params.credentialDefinition,
    JSON.stringify(params.credentialDefinitionKey),
    JSON.stringify(params.credentialRequest),
    JSON.stringify(params.revocationRegistryKey),
    JSON.stringify(params.revocationRegistryInfo),
    params.revocationRegistryDefinitionDid,
    JSON.stringify(params.blindingFactors),
    JSON.stringify(params.masterSecret),
    params.issuerDid,
    params.subjectDid
  );

  return JSON.parse(credential);
}

/**
 * issues a credential for a given definition for a given subject
 * @param {object} params parameters for the revocation registry
 * @param {object} params.proofRequest credential definition object
 * @param {object} params.credential credential request object
 * @param {object} params.revocationRegistryDefinition revocation registry definition object
 * @param {object} params.revocationWitness revocation registry definition object
 * @param {object} params.masterSecret master secret object
 */
async function presentProof(params) {

  if(params && !params.proofRequest) {
    throw new Error(`proofRequest must be provided in params`);
  }
  if(params && !params.credential) {
    throw new Error(`credential must be provided in params`);
  }

  if(params && !params.revocationWitness) {
    throw new Error(`schema must be provided in params`);
  }

  if(params && !params.revocationRegistryDefinition) {
    throw new Error(`revocationRegistryDefinition must be provided in params`);
  }

  if(params && !params.masterSecret) {
    throw new Error(`masterSecret must be provided in params`);
  }

  const proof = await wasm.present_proof(
    JSON.stringify(params.proofRequest),
    JSON.stringify(params.credential),
    JSON.stringify(params.masterSecret),
    JSON.stringify(params.revocationWitness),
  );

  return JSON.parse(proof);
}

/**
 * issues a credential for a given definition for a given subject
 * @param {object} params parameters for the revocation registry
 * @param {object} params.proof credential definition object
 * @param {object} params.proofRequest credential definition object
 * @param {object} params.credentialDefinition credential request object
 * @param {object} params.schema revocation registry definition object
 * @param {object} params.revocationRegistryDefinition revocation registry definition object
 */
async function verifyProof(params) {

  if(params && !params.proof) {
    throw new Error(`proofRequest must be provided in params`);
  }

  if(params && !params.proofRequest) {
    throw new Error(`proofRequest must be provided in params`);
  }
  if(params && !params.credentialDefinition) {
    throw new Error(`credential must be provided in params`);
  }

  if(params && !params.schema) {
    throw new Error(`schema must be provided in params`);
  }

  if(params && !params.revocationRegistryDefinition) {
    throw new Error(`revocationRegistryDefinition must be provided in params`);
  }

  const verifiedProof = await wasm.verify_proof(
    JSON.stringify(params.proof),
    JSON.stringify(params.proofRequest),
    JSON.stringify(params.credentialDefinition),
    JSON.stringify(params.schema),
    JSON.stringify(params.revocationRegistryDefinition),
  );

  return JSON.parse(verifiedProof);
}

async function workflow_self_issue_credential(issuerDID, schemaDid, definitionDid, definitionKey, revRevDid, revRegInfo, revRegPk, values) {
  const ms = createMasterSecret();

  const proposal = await createCredentialProposal({
    schemaId: schemaDid,
    issuerDid: issuerDID,
    subjectDid: issuerDID
  });

  const offer = await createCredentialOffer({
    proposal,
    credentialDefinitionId: definitionDid
  });

  const request = await createCredentialRequest({
    offer,
    masterSecret: ms,
    credentialValues: values
  });

  const credential = await issueCredential({
    credentialDefinition: definitionDid,
    credentialDefinitionKey: definitionKey,
    credentialRequest: request.request,
    revocationRegistryKey: revRegPk,
    revocationRegistryInfo: revRegInfo,
    revocationRegistryDefinitionDid: revRevDid,
    blindingFactors: request.blindingFactors,
    masterSecret: ms,
    issuerDid: issuerDID,
    subjectDid: issuerDID
  })

  return {
    credential,
    ms
  };

}

async function workflow_present_proof(schemaId, credential, ms, revealedAttributes) {

  const proof = await requestProof({
    schemaId: TEST_SCHEMA_ID,
    issuerDid: issuerDID,
    proverDid: issuerDID,
    revealedAttributes
  })

  const presentedProof = await presentProof({
    proofRequest: proof,
    credentialDefinition: TEST_CRED_DEF.definition,
    credential: credential.credential,
    schema: TEST_SCHEMA,
    revocationRegistryDefinition: TEST_REV_REG.revocationRegistryDefinition,
    revocationWitness: credential.revocationState.witness,
    masterSecret: ms
  })

  return presentedProof;

}

async function workflow_verify_proof(proofRequest, presentedProof) {

  const verifiedProof = await verifyProof({
    proof: presentedProof,
    proofRequest: proof,
    credentialDefinition: TEST_CRED_DEF.definition,
    schema: TEST_SCHEMA,
    revocationRegistryDefinition: TEST_REV_REG.revocationRegistryDefinition
  })

  return verifiedProof;
}

const vadeApi = {
  whitelistIdentity,
  createSchema,
  createCredentialDefinition,
  createMasterSecret,
  requestProof,
  createCredentialProposal,
  createCredentialOffer,
  createCredentialRequest,
  createRevocationRegistry,
  issueCredential,
  presentProof,
  verifyProof,
  workflow_verify_proof,
  workflow_present_proof,
  workflow_self_issue_credential,
  workflow_create_creds_setup
}

module.exports = vadeApi;