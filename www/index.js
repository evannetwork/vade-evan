import * as wasm from "vade-tnt";
//const wasm = require('vade-tnt');
const SUBSTRATE_URL = '13.69.59.185';

/**
 * whitelists a specific evan did on substrate that this private key can create DIDs  
 * @param {string} privateKey 
 * @param {string} identity 
 */
async function whitelistIdentity(privateKey, identity) {
  if(!identity.startsWith('did')) {
    throw new Error(`identity should start with did:evan:...`);
  }

  await wasm.whitelist_identity(privateKey, identity);
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

  if(params && !params.credentialDefinition) {
    throw new Error(`credentialDefinition must be provided in params`);
  }

  if(params && !params.masterSecret) {
    throw new Error(`masterSecret must be provided in params`);
  }

  if(params && !params.credentialValues) {
    throw new Error(`credentialValues must be provided in params`);
  }

  const request = await wasm.create_credential_request(
    JSON.stringify(params.credentialDefinition),
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

  if(params && !params.revocationRegistryDefinition) {
    throw new Error(`revocationRegistryDefinition must be provided in params`);
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
    JSON.stringify(params.credentialDefinition),
    JSON.stringify(params.credentialDefinitionKey),
    JSON.stringify(params.credentialRequest),
    JSON.stringify(params.revocationRegistryKey),
    JSON.stringify(params.revocationRegistryInfo),
    JSON.stringify(params.revocationRegistryDefinition),
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


/*const vadeApi = {
  whitelistIdentity: async(privateKey, identity) {

  }
}*/
//wasm.watch_event("127.0.0.1")
//wasm.send_extrinsic("127.0.0.1", Date.now() )
const sleep = m => new Promise(r => setTimeout(r, m))


const properties = {
  eigenschaft1: {
    type: "string"
  }
}


const requiredProperties = ["eigenschaft1"];
const issuerDID = "did:evan:testcore:0x9670f7974e7021e4940c56d47f6b31fdfdd37de8";
const issuerPK = "4ea724e22ede0b7bea88771612485205cfc344131a16b8ab23d4970132be8dab";

const TEST_SCHEMA_ID = "0x9278ffcf19331a2a43fa1766021a2ae9c27f2a14561c9511402c30e1ffc31dfd";
const TEST_SCHEMA = {
  "id":"0x9278ffcf19331a2a43fa1766021a2ae9c27f2a14561c9511402c30e1ffc31dfd",
  "type":"EvanVCSchema",
  "name":"TestSchema",
  "author":"did:evan:testcore:0x9670f7974e7021e4940c56d47f6b31fdfdd37de8",
  "createdAt":"2020-06-09T06:52:24.072Z",
  "description":"TestDesc",
  "properties":{
    "eigenschaft1":{"type":"string"}
  },
  "required":["eigenschaft1"],
  "additionalProperties":false,
  "proof":{
    "type":"EcdsaPublicKeySecp256k1",
    "created":"2020-06-09T06:52:24.073Z",
    "proofPurpose":"assertionMethod",
    "verificationMethod":"did:evan:testcore:0x9670f7974e7021e4940c56d47f6b31fdfdd37de8#key1",
    "jws":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIwLTA2LTA5VDA2OjUyOjI0LjA3M1oiLCJkb2MiOnsiaWQiOiIweDkyNzhmZmNmMTkzMzFhMmE0M2ZhMTc2NjAyMWEyYWU5YzI3ZjJhMTQ1NjFjOTUxMTQwMmMzMGUxZmZjMzFkZmQiLCJ0eXBlIjoiRXZhblZDU2NoZW1hIiwibmFtZSI6IlRlc3RTY2hlbWEiLCJhdXRob3IiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDk2NzBmNzk3NGU3MDIxZTQ5NDBjNTZkNDdmNmIzMWZkZmRkMzdkZTgiLCJjcmVhdGVkQXQiOiIyMDIwLTA2LTA5VDA2OjUyOjI0LjA3MloiLCJkZXNjcmlwdGlvbiI6IlRlc3REZXNjIiwicHJvcGVydGllcyI6eyJlaWdlbnNjaGFmdDEiOnsidHlwZSI6InN0cmluZyJ9fSwicmVxdWlyZWQiOlsiZWlnZW5zY2hhZnQxIl0sImFkZGl0aW9uYWxQcm9wZXJ0aWVzIjpmYWxzZX0sImlzcyI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4OTY3MGY3OTc0ZTcwMjFlNDk0MGM1NmQ0N2Y2YjMxZmRmZGQzN2RlOCJ9.5wHjhYlax04zXe3yXhTqwhjA243wWW7bB0cN-TUMkq9siuYLxQujODJTeCRKTwEP9UsbCfWTZBMYs5kg2JpF1gA"
  }
}
const TEST_CRED_DEF = {
  "definition":{
    "id":"0xb9e84ae0bcf27ae4241c8f8d76ac10503e4819d8649aa13ad693e512fe2c8240",
    "type":"EvanZKPCredentialDefinition",
    "issuer":"did:evan:testcore:0x9670f7974e7021e4940c56d47f6b31fdfdd37de8",
    "schema":"0x9278ffcf19331a2a43fa1766021a2ae9c27f2a14561c9511402c30e1ffc31dfd",
    "createdAt":"2020-06-09T07:33:42.063Z",
    "publicKey":{
      "p_key":{
        "n":"429071208281977257668360830675226496274373897214287528492816748755066930809009",
        "s":"239700850255480049770288772149338160061226897289598571504559768086493266411554",
        "r":{
          "master_secret":"332942093372813324192311484612707720597379264154828850220783918352495868145049",
          "eigenschaft1":"316801705121971196938210423780993999751979396251014125847593924882555817820013"
        },
        "rctxt":"16053674233734949682360905756133873249004292253359832244374956302627204091238",
        "z":"250242074788883566506143375619366127772040361081353695988592897919958963657934"
      },
      "r_key":{
        "g":"1 035EE071094D8CF03D2098E03323189ACC363105A6575571FB739A8801ECCD5F 1 13556BDE94FC730F79FFB323108EC85894277C0748393E941754A0EE2E1D3772 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8",
        "g_dash":"1 18AF518D35D2C2233B5D81BA3425C617C1FDA5D94FCEE5B7822FF724316ACC4F 1 1E9DB9C67866B17ABC0831B36A083C98632B523EE8E6ABF5E3F5C2C9270400A8 1 12663DCDACF7B9693904191C2BB8FBD074278481FFFCA07695DD394AFFF12F01 1 02C909606086DFC35FC1724F6C92ED7E439695320DF6E3707C8667C7A34DBF66 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000",
        "h":"1 22349B681925A02D302D4F6574A5F2C4E8B22B23DA7FA4C1218514110997E684 1 15C6F87776C88CE3D1C5A97EF41197944344D7ADA2FA01D4A83D6092AAF3C9BD 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8",
        "h0":"1 11739A93B545A6E6BA905C2C88285223D0BBBBF82E022FB75634C5D214D633D1 1 1951678A6C43E601157D6D73E2CAA8B016428E382BAE1FD57708A0D8FEA6BBC3 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8",
        "h1":"1 0ECE4BDF0B7904450E37CDFC3C8A358484401F7153FF6CF28AF2A8BFEE90E166 1 24712946DF101784D00B0756F485A8D8FDA3C11B76A13126867C5C0AAE0879E4 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8",
        "h2":"1 1ACAAC3F6234342A31E9F56132D49B689708E9AD751DC52DBF02B844D56ADDDA 1 192230EAEBF7320BDAAEEC83D184517BC7A4216CDDD607C8B737B236F6C69EF1 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8",
        "htilde":"1 085E91194C355641E168E26F5EE7E67F3D124CAB8F95B8AB3F918189768C6865 1 14984E2267A68B074426B3F748896655DE8601386C4E0C5EE4C2F3666AAFCC66 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8",
        "h_cap":"1 17D4686014F8653D88236941ABCED4FD77A81D7810CF5F4FBB812DAE8EA92F9C 1 1223C8BCFDB37D3F5620A6B3046091D64CA66F8E05ACD698BB79C9E16A48C6B3 1 1F722EAE470A729A89141B4831AA22A6D269D98ACACB09FA7AAEBD75E2005C8D 1 130DB1E583AD4152E701BF1FEFAA1CBCEBC6DAC26D402F7E9922F98A58024DAA 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000",
        "u":"1 0B8E5920218905136E7D9CFBC95493173058B7B4308463D14FF777E4D5C4AB24 1 013F18F323AB1300124A80C6404796B7DFA3CCB81137CA5A2CEFB369FA6B5DE9 1 08B383D5F0CF14B691996411557A08C1F7A7869FF79C04736393583F6C4616D7 1 14FA98FCB1B9D7103CD9C01DB246F288124390B2E201C11E874B760F68441CA9 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000",
        "pk":"1 24076A28D247E1216C46134CFAAA55DC79F35090EEA131AEFFA5D9BFD5A8B5E8 1 13D7802494181C0054BCD557F6B5E649729159AAE8887A72AB3CCFD3E83DE813 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8","y":"1 1600B38A296952A3E73ACCB90F56EA18262D04BDD91981E6DC4C9611E6206C58 1 1B26BDC950C3D5080D421BFD277440BD9920C309AE95981E1DEC652CBBC4F280 1 09B69953EEB80303705A301F50D0A946C4716EFD8C85513B443295621BEDFD60 1 0E4844110B8E13D21A6F270BCAD4E65533463D91E79D9871AC473D5A5ED39716 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000"
      }
    },
    "publicKeyCorrectnessProof":{
      "c":"45893911886858924745380144620470930225986342249029224426060574049443959656182",
      "xz_cap":"3214748132482477710514691403794205430444487586839098453233651336294621283639407800531712950310751832181280867453590420298803605734139638324888330535197522",
      "xr_cap":[
        ["master_secret","2684104208751931728496784475217089128227964181476045394045172008701197016920320649947632731000787109337446354873256391852895340955663098888702764965731051"],
        ["eigenschaft1","4795991097966875535725011476309171674457853995928963109226332838159569599031866959670329489921586388692506643392664625980580330611878046194115621825537857"]
      ]
    },
    "proof":{
      "type":"EcdsaPublicKeySecp256k1",
      "created":"2020-06-09T07:34:18.071Z",
      "proofPurpose":"assertionMethod",
      "verificationMethod":"did:evan:testcore:0x9670f7974e7021e4940c56d47f6b31fdfdd37de8#key1",
      "jws":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIwLTA2LTA5VDA3OjM0OjE4LjA3MVoiLCJkb2MiOnsiaWQiOiIweGI5ZTg0YWUwYmNmMjdhZTQyNDFjOGY4ZDc2YWMxMDUwM2U0ODE5ZDg2NDlhYTEzYWQ2OTNlNTEyZmUyYzgyNDAiLCJ0eXBlIjoiRXZhblpLUENyZWRlbnRpYWxEZWZpbml0aW9uIiwiaXNzdWVyIjoiZGlkOmV2YW46dGVzdGNvcmU6MHg5NjcwZjc5NzRlNzAyMWU0OTQwYzU2ZDQ3ZjZiMzFmZGZkZDM3ZGU4Iiwic2NoZW1hIjoiMHg5Mjc4ZmZjZjE5MzMxYTJhNDNmYTE3NjYwMjFhMmFlOWMyN2YyYTE0NTYxYzk1MTE0MDJjMzBlMWZmYzMxZGZkIiwiY3JlYXRlZEF0IjoiMjAyMC0wNi0wOVQwNzozMzo0Mi4wNjNaIiwicHVibGljS2V5Ijp7InBfa2V5Ijp7Im4iOiI0MjkwNzEyMDgyODE5NzcyNTc2NjgzNjA4MzA2NzUyMjY0OTYyNzQzNzM4OTcyMTQyODc1Mjg0OTI4MTY3NDg3NTUwNjY5MzA4MDkwMDkiLCJzIjoiMjM5NzAwODUwMjU1NDgwMDQ5NzcwMjg4NzcyMTQ5MzM4MTYwMDYxMjI2ODk3Mjg5NTk4NTcxNTA0NTU5NzY4MDg2NDkzMjY2NDExNTU0IiwiciI6eyJtYXN0ZXJfc2VjcmV0IjoiMzMyOTQyMDkzMzcyODEzMzI0MTkyMzExNDg0NjEyNzA3NzIwNTk3Mzc5MjY0MTU0ODI4ODUwMjIwNzgzOTE4MzUyNDk1ODY4MTQ1MDQ5IiwiZWlnZW5zY2hhZnQxIjoiMzE2ODAxNzA1MTIxOTcxMTk2OTM4MjEwNDIzNzgwOTkzOTk5NzUxOTc5Mzk2MjUxMDE0MTI1ODQ3NTkzOTI0ODgyNTU1ODE3ODIwMDEzIn0sInJjdHh0IjoiMTYwNTM2NzQyMzM3MzQ5NDk2ODIzNjA5MDU3NTYxMzM4NzMyNDkwMDQyOTIyNTMzNTk4MzIyNDQzNzQ5NTYzMDI2MjcyMDQwOTEyMzgiLCJ6IjoiMjUwMjQyMDc0Nzg4ODgzNTY2NTA2MTQzMzc1NjE5MzY2MTI3NzcyMDQwMzYxMDgxMzUzNjk1OTg4NTkyODk3OTE5OTU4OTYzNjU3OTM0In0sInJfa2V5Ijp7ImciOiIxIDAzNUVFMDcxMDk0RDhDRjAzRDIwOThFMDMzMjMxODlBQ0MzNjMxMDVBNjU3NTU3MUZCNzM5QTg4MDFFQ0NENUYgMSAxMzU1NkJERTk0RkM3MzBGNzlGRkIzMjMxMDhFQzg1ODk0Mjc3QzA3NDgzOTNFOTQxNzU0QTBFRTJFMUQzNzcyIDIgMDk1RTQ1RERGNDE3RDA1RkIxMDkzM0ZGQzYzRDQ3NDU0OEI3RkZGRjc4ODg4MDJGMDdGRkZGRkY3RDA3QThBOCIsImdfZGFzaCI6IjEgMThBRjUxOEQzNUQyQzIyMzNCNUQ4MUJBMzQyNUM2MTdDMUZEQTVEOTRGQ0VFNUI3ODIyRkY3MjQzMTZBQ0M0RiAxIDFFOURCOUM2Nzg2NkIxN0FCQzA4MzFCMzZBMDgzQzk4NjMyQjUyM0VFOEU2QUJGNUUzRjVDMkM5MjcwNDAwQTggMSAxMjY2M0RDREFDRjdCOTY5MzkwNDE5MUMyQkI4RkJEMDc0Mjc4NDgxRkZGQ0EwNzY5NUREMzk0QUZGRjEyRjAxIDEgMDJDOTA5NjA2MDg2REZDMzVGQzE3MjRGNkM5MkVEN0U0Mzk2OTUzMjBERjZFMzcwN0M4NjY3QzdBMzREQkY2NiAyIDA5NUU0NURERjQxN0QwNUZCMTA5MzNGRkM2M0Q0NzQ1NDhCN0ZGRkY3ODg4ODAyRjA3RkZGRkZGN0QwN0E4QTggMSAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwiaCI6IjEgMjIzNDlCNjgxOTI1QTAyRDMwMkQ0RjY1NzRBNUYyQzRFOEIyMkIyM0RBN0ZBNEMxMjE4NTE0MTEwOTk3RTY4NCAxIDE1QzZGODc3NzZDODhDRTNEMUM1QTk3RUY0MTE5Nzk0NDM0NEQ3QURBMkZBMDFENEE4M0Q2MDkyQUFGM0M5QkQgMiAwOTVFNDVEREY0MTdEMDVGQjEwOTMzRkZDNjNENDc0NTQ4QjdGRkZGNzg4ODgwMkYwN0ZGRkZGRjdEMDdBOEE4IiwiaDAiOiIxIDExNzM5QTkzQjU0NUE2RTZCQTkwNUMyQzg4Mjg1MjIzRDBCQkJCRjgyRTAyMkZCNzU2MzRDNUQyMTRENjMzRDEgMSAxOTUxNjc4QTZDNDNFNjAxMTU3RDZENzNFMkNBQThCMDE2NDI4RTM4MkJBRTFGRDU3NzA4QTBEOEZFQTZCQkMzIDIgMDk1RTQ1RERGNDE3RDA1RkIxMDkzM0ZGQzYzRDQ3NDU0OEI3RkZGRjc4ODg4MDJGMDdGRkZGRkY3RDA3QThBOCIsImgxIjoiMSAwRUNFNEJERjBCNzkwNDQ1MEUzN0NERkMzQzhBMzU4NDg0NDAxRjcxNTNGRjZDRjI4QUYyQThCRkVFOTBFMTY2IDEgMjQ3MTI5NDZERjEwMTc4NEQwMEIwNzU2RjQ4NUE4RDhGREEzQzExQjc2QTEzMTI2ODY3QzVDMEFBRTA4NzlFNCAyIDA5NUU0NURERjQxN0QwNUZCMTA5MzNGRkM2M0Q0NzQ1NDhCN0ZGRkY3ODg4ODAyRjA3RkZGRkZGN0QwN0E4QTgiLCJoMiI6IjEgMUFDQUFDM0Y2MjM0MzQyQTMxRTlGNTYxMzJENDlCNjg5NzA4RTlBRDc1MURDNTJEQkYwMkI4NDRENTZBREREQSAxIDE5MjIzMEVBRUJGNzMyMEJEQUFFRUM4M0QxODQ1MTdCQzdBNDIxNkNEREQ2MDdDOEI3MzdCMjM2RjZDNjlFRjEgMiAwOTVFNDVEREY0MTdEMDVGQjEwOTMzRkZDNjNENDc0NTQ4QjdGRkZGNzg4ODgwMkYwN0ZGRkZGRjdEMDdBOEE4IiwiaHRpbGRlIjoiMSAwODVFOTExOTRDMzU1NjQxRTE2OEUyNkY1RUU3RTY3RjNEMTI0Q0FCOEY5NUI4QUIzRjkxODE4OTc2OEM2ODY1IDEgMTQ5ODRFMjI2N0E2OEIwNzQ0MjZCM0Y3NDg4OTY2NTVERTg2MDEzODZDNEUwQzVFRTRDMkYzNjY2QUFGQ0M2NiAyIDA5NUU0NURERjQxN0QwNUZCMTA5MzNGRkM2M0Q0NzQ1NDhCN0ZGRkY3ODg4ODAyRjA3RkZGRkZGN0QwN0E4QTgiLCJoX2NhcCI6IjEgMTdENDY4NjAxNEY4NjUzRDg4MjM2OTQxQUJDRUQ0RkQ3N0E4MUQ3ODEwQ0Y1RjRGQkI4MTJEQUU4RUE5MkY5QyAxIDEyMjNDOEJDRkRCMzdEM0Y1NjIwQTZCMzA0NjA5MUQ2NENBNjZGOEUwNUFDRDY5OEJCNzlDOUUxNkE0OEM2QjMgMSAxRjcyMkVBRTQ3MEE3MjlBODkxNDFCNDgzMUFBMjJBNkQyNjlEOThBQ0FDQjA5RkE3QUFFQkQ3NUUyMDA1QzhEIDEgMTMwREIxRTU4M0FENDE1MkU3MDFCRjFGRUZBQTFDQkNFQkM2REFDMjZENDAyRjdFOTkyMkY5OEE1ODAyNERBQSAyIDA5NUU0NURERjQxN0QwNUZCMTA5MzNGRkM2M0Q0NzQ1NDhCN0ZGRkY3ODg4ODAyRjA3RkZGRkZGN0QwN0E4QTggMSAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwidSI6IjEgMEI4RTU5MjAyMTg5MDUxMzZFN0Q5Q0ZCQzk1NDkzMTczMDU4QjdCNDMwODQ2M0QxNEZGNzc3RTRENUM0QUIyNCAxIDAxM0YxOEYzMjNBQjEzMDAxMjRBODBDNjQwNDc5NkI3REZBM0NDQjgxMTM3Q0E1QTJDRUZCMzY5RkE2QjVERTkgMSAwOEIzODNENUYwQ0YxNEI2OTE5OTY0MTE1NTdBMDhDMUY3QTc4NjlGRjc5QzA0NzM2MzkzNTgzRjZDNDYxNkQ3IDEgMTRGQTk4RkNCMUI5RDcxMDNDRDlDMDFEQjI0NkYyODgxMjQzOTBCMkUyMDFDMTFFODc0Qjc2MEY2ODQ0MUNBOSAyIDA5NUU0NURERjQxN0QwNUZCMTA5MzNGRkM2M0Q0NzQ1NDhCN0ZGRkY3ODg4ODAyRjA3RkZGRkZGN0QwN0E4QTggMSAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwicGsiOiIxIDI0MDc2QTI4RDI0N0UxMjE2QzQ2MTM0Q0ZBQUE1NURDNzlGMzUwOTBFRUExMzFBRUZGQTVEOUJGRDVBOEI1RTggMSAxM0Q3ODAyNDk0MTgxQzAwNTRCQ0Q1NTdGNkI1RTY0OTcyOTE1OUFBRTg4ODdBNzJBQjNDQ0ZEM0U4M0RFODEzIDIgMDk1RTQ1RERGNDE3RDA1RkIxMDkzM0ZGQzYzRDQ3NDU0OEI3RkZGRjc4ODg4MDJGMDdGRkZGRkY3RDA3QThBOCIsInkiOiIxIDE2MDBCMzhBMjk2OTUyQTNFNzNBQ0NCOTBGNTZFQTE4MjYyRDA0QkREOTE5ODFFNkRDNEM5NjExRTYyMDZDNTggMSAxQjI2QkRDOTUwQzNENTA4MEQ0MjFCRkQyNzc0NDBCRDk5MjBDMzA5QUU5NTk4MUUxREVDNjUyQ0JCQzRGMjgwIDEgMDlCNjk5NTNFRUI4MDMwMzcwNUEzMDFGNTBEMEE5NDZDNDcxNkVGRDhDODU1MTNCNDQzMjk1NjIxQkVERkQ2MCAxIDBFNDg0NDExMEI4RTEzRDIxQTZGMjcwQkNBRDRFNjU1MzM0NjNEOTFFNzlEOTg3MUFDNDczRDVBNUVEMzk3MTYgMiAwOTVFNDVEREY0MTdEMDVGQjEwOTMzRkZDNjNENDc0NTQ4QjdGRkZGNzg4ODgwMkYwN0ZGRkZGRjdEMDdBOEE4IDEgMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCJ9fSwicHVibGljS2V5Q29ycmVjdG5lc3NQcm9vZiI6eyJjIjoiNDU4OTM5MTE4ODY4NTg5MjQ3NDUzODAxNDQ2MjA0NzA5MzAyMjU5ODYzNDIyNDkwMjkyMjQ0MjYwNjA1NzQwNDk0NDM5NTk2NTYxODIiLCJ4el9jYXAiOiIzMjE0NzQ4MTMyNDgyNDc3NzEwNTE0NjkxNDAzNzk0MjA1NDMwNDQ0NDg3NTg2ODM5MDk4NDUzMjMzNjUxMzM2Mjk0NjIxMjgzNjM5NDA3ODAwNTMxNzEyOTUwMzEwNzUxODMyMTgxMjgwODY3NDUzNTkwNDIwMjk4ODAzNjA1NzM0MTM5NjM4MzI0ODg4MzMwNTM1MTk3NTIyIiwieHJfY2FwIjpbWyJtYXN0ZXJfc2VjcmV0IiwiMjY4NDEwNDIwODc1MTkzMTcyODQ5Njc4NDQ3NTIxNzA4OTEyODIyNzk2NDE4MTQ3NjA0NTM5NDA0NTE3MjAwODcwMTE5NzAxNjkyMDMyMDY0OTk0NzYzMjczMTAwMDc4NzEwOTMzNzQ0NjM1NDg3MzI1NjM5MTg1Mjg5NTM0MDk1NTY2MzA5ODg4ODcwMjc2NDk2NTczMTA1MSJdLFsiZWlnZW5zY2hhZnQxIiwiNDc5NTk5MTA5Nzk2Njg3NTUzNTcyNTAxMTQ3NjMwOTE3MTY3NDQ1Nzg1Mzk5NTkyODk2MzEwOTIyNjMzMjgzODE1OTU2OTU5OTAzMTg2Njk1OTY3MDMyOTQ4OTkyMTU4NjM4ODY5MjUwNjY0MzM5MjY2NDYyNTk4MDU4MDMzMDYxMTg3ODA0NjE5NDExNTYyMTgyNTUzNzg1NyJdXX19LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDk2NzBmNzk3NGU3MDIxZTQ5NDBjNTZkNDdmNmIzMWZkZmRkMzdkZTgifQ.4luxuorIdaRzoBukHgdbuxnNBLeroACRyRKJrTEtA2omp1x9-xAfUsATfa1xZxh2W9FkvdeMykhnxsOtWH6NXQE"
    }
  },
  "definitionKey":{
    "p_key":{
      "p":"318445554515577184723567014661071703271",
      "q":"336848169332026797879540958916681648831"
    },
    "r_key":{
      "x":"1AA715914C0E4BFCFFCE65DBF7EA727205D712D99708A6F7320BE7DBD966EF16",
      "sk":"200148171513F8B6CC6C166550042FD0CB5CCBBD63F6EA60676CAE22EEC6FFC5"
    }
  }
}

const TEST_REV_REG = {
  "privateKey":{
    "gamma":"07C280086C5526D9563E2B09C7A8D84F1C08193BF2895417F621E8398F18B139"
  },
  "revocationInfo":{
    "definitionId":"0xf6c7a439b7ff31b997dc96d8803f47e8cc1f1e036a48962032c1e7633af5aa84",
    "nextUnusedId":1,
    "usedIds":[]
  },
  "revocationRegistryDefinition":{
    "id":"0xf6c7a439b7ff31b997dc96d8803f47e8cc1f1e036a48962032c1e7633af5aa84",
    "credentialDefinition":"0xb9e84ae0bcf27ae4241c8f8d76ac10503e4819d8649aa13ad693e512fe2c8240",
    "updatedAt":"2020-06-09T07:54:14.828Z",
    "registry":{
      "accum":"21 13FC157987EDCA84CD6BD9569C4EA174E5E946DC53D36FE19B22886D1E0E00BCB 21 122464098DA321DE72BD5C495FFB0F70BD710AD511E92285C50D7B3C5180D2090 6 793E2403B0E9BC5CE8104BFFBE71EBCCBE1BFCA2B5390B890C0CE0418281DDF3 4 1D055B24E7426C8B6AE87988AD5DD910A2E514E25BF3DC7FAF64E377BB3A2A02 6 621B1DA0F2550128221160B5A607D8D42E6C1697EF538B0892366C8B11B84867 4 18719AB4142ABFD997FD4F7162EAC928FE7FC485D82A4B789FA71A119C75F5F5"
    },
    "registryDelta":{
      "accum":"21 13FC157987EDCA84CD6BD9569C4EA174E5E946DC53D36FE19B22886D1E0E00BCB 21 122464098DA321DE72BD5C495FFB0F70BD710AD511E92285C50D7B3C5180D2090 6 793E2403B0E9BC5CE8104BFFBE71EBCCBE1BFCA2B5390B890C0CE0418281DDF3 4 1D055B24E7426C8B6AE87988AD5DD910A2E514E25BF3DC7FAF64E377BB3A2A02 6 621B1DA0F2550128221160B5A607D8D42E6C1697EF538B0892366C8B11B84867 4 18719AB4142ABFD997FD4F7162EAC928FE7FC485D82A4B789FA71A119C75F5F5"
    },
    "deltaHistory":[
      {
        "created":1591689254,
        "delta":{
          "accum":"21 13FC157987EDCA84CD6BD9569C4EA174E5E946DC53D36FE19B22886D1E0E00BCB 21 122464098DA321DE72BD5C495FFB0F70BD710AD511E92285C50D7B3C5180D2090 6 793E2403B0E9BC5CE8104BFFBE71EBCCBE1BFCA2B5390B890C0CE0418281DDF3 4 1D055B24E7426C8B6AE87988AD5DD910A2E514E25BF3DC7FAF64E377BB3A2A02 6 621B1DA0F2550128221160B5A607D8D42E6C1697EF538B0892366C8B11B84867 4 18719AB4142ABFD997FD4F7162EAC928FE7FC485D82A4B789FA71A119C75F5F5"
        }
      }
    ],
    "tails":{
      "size":85,
      "current_index":0,
      "g_dash":"1 18AF518D35D2C2233B5D81BA3425C617C1FDA5D94FCEE5B7822FF724316ACC4F 1 1E9DB9C67866B17ABC0831B36A083C98632B523EE8E6ABF5E3F5C2C9270400A8 1 12663DCDACF7B9693904191C2BB8FBD074278481FFFCA07695DD394AFFF12F01 1 02C909606086DFC35FC1724F6C92ED7E439695320DF6E3707C8667C7A34DBF66 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000",
      "gamma":"07C280086C5526D9563E2B09C7A8D84F1C08193BF2895417F621E8398F18B139"
    },
    "revocationPublicKey":{
      "z":"1 12A21FC7347AB3AC774B47FE3FC051381BA775DA89ECCEDCC98D5B820A152581 1 1409C523874A2F1003A4EF3BE9BFBC64234CCB1C7362983E9D970A6E891010B7 1 1F93647317880A90DF74C4A7B54572FBE24DFD3865D862AA76A11330A393FBE5 1 1926D7973830750F5252D4EBDB776FFAE284FCA8E37658B4A0B61F9C5FD4C43D 1 05F9950855685FC996DDA9B239B7D84F48BF0CCA7C8656DB9CB8A6649CB7AB0F 1 08038A4A6265FDED75AFA0E533EACBD179F1F4FC64CE5CC2BC948BE870916525 1 24A9E54EE2EE9C1CD6EA35CAA8759136C5961212148545D51E1F187A9C766835 1 1DBD64336430937A47ABAAA8D2A7517E56A0F8EA1015414025F7B567F5387F27 1 195131B02AB70721BDEFC9EE70039F7A02682FC78E3E0999FD1027C5BA9651CB 1 24241C316895CB058AE22D2CDB5465E244BB64D8A400E5EFA04AD98817F3C422 1 1F81E22BF3B9BAE49662A90C3205ECCBB7A8A4D8876FAB294BDD7799282BC43F 1 1561CB7A9ADEDFC3BCD6BB01AE939AD8DD0AAD70FA29C97668A254F1EE8CF94C"
    },
    "maximumCredentialCount":42,
    "proof":{
      "type":"EcdsaPublicKeySecp256k1",
      "created":"2020-06-09T07:54:14.846Z",
      "proofPurpose":"assertionMethod",
      "verificationMethod":"did:evan:testcore:0x9670f7974e7021e4940c56d47f6b31fdfdd37de8#key1",
      "jws":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIwLTA2LTA5VDA3OjU0OjE0Ljg0NloiLCJkb2MiOnsiaWQiOiIweGY2YzdhNDM5YjdmZjMxYjk5N2RjOTZkODgwM2Y0N2U4Y2MxZjFlMDM2YTQ4OTYyMDMyYzFlNzYzM2FmNWFhODQiLCJjcmVkZW50aWFsRGVmaW5pdGlvbiI6IjB4YjllODRhZTBiY2YyN2FlNDI0MWM4ZjhkNzZhYzEwNTAzZTQ4MTlkODY0OWFhMTNhZDY5M2U1MTJmZTJjODI0MCIsInVwZGF0ZWRBdCI6IjIwMjAtMDYtMDlUMDc6NTQ6MTQuODI4WiIsInJlZ2lzdHJ5Ijp7ImFjY3VtIjoiMjEgMTNGQzE1Nzk4N0VEQ0E4NENENkJEOTU2OUM0RUExNzRFNUU5NDZEQzUzRDM2RkUxOUIyMjg4NkQxRTBFMDBCQ0IgMjEgMTIyNDY0MDk4REEzMjFERTcyQkQ1QzQ5NUZGQjBGNzBCRDcxMEFENTExRTkyMjg1QzUwRDdCM0M1MTgwRDIwOTAgNiA3OTNFMjQwM0IwRTlCQzVDRTgxMDRCRkZCRTcxRUJDQ0JFMUJGQ0EyQjUzOTBCODkwQzBDRTA0MTgyODFEREYzIDQgMUQwNTVCMjRFNzQyNkM4QjZBRTg3OTg4QUQ1REQ5MTBBMkU1MTRFMjVCRjNEQzdGQUY2NEUzNzdCQjNBMkEwMiA2IDYyMUIxREEwRjI1NTAxMjgyMjExNjBCNUE2MDdEOEQ0MkU2QzE2OTdFRjUzOEIwODkyMzY2QzhCMTFCODQ4NjcgNCAxODcxOUFCNDE0MkFCRkQ5OTdGRDRGNzE2MkVBQzkyOEZFN0ZDNDg1RDgyQTRCNzg5RkE3MUExMTlDNzVGNUY1In0sInJlZ2lzdHJ5RGVsdGEiOnsiYWNjdW0iOiIyMSAxM0ZDMTU3OTg3RURDQTg0Q0Q2QkQ5NTY5QzRFQTE3NEU1RTk0NkRDNTNEMzZGRTE5QjIyODg2RDFFMEUwMEJDQiAyMSAxMjI0NjQwOThEQTMyMURFNzJCRDVDNDk1RkZCMEY3MEJENzEwQUQ1MTFFOTIyODVDNTBEN0IzQzUxODBEMjA5MCA2IDc5M0UyNDAzQjBFOUJDNUNFODEwNEJGRkJFNzFFQkNDQkUxQkZDQTJCNTM5MEI4OTBDMENFMDQxODI4MURERjMgNCAxRDA1NUIyNEU3NDI2QzhCNkFFODc5ODhBRDVERDkxMEEyRTUxNEUyNUJGM0RDN0ZBRjY0RTM3N0JCM0EyQTAyIDYgNjIxQjFEQTBGMjU1MDEyODIyMTE2MEI1QTYwN0Q4RDQyRTZDMTY5N0VGNTM4QjA4OTIzNjZDOEIxMUI4NDg2NyA0IDE4NzE5QUI0MTQyQUJGRDk5N0ZENEY3MTYyRUFDOTI4RkU3RkM0ODVEODJBNEI3ODlGQTcxQTExOUM3NUY1RjUifSwiZGVsdGFIaXN0b3J5IjpbeyJjcmVhdGVkIjoxNTkxNjg5MjU0LCJkZWx0YSI6eyJhY2N1bSI6IjIxIDEzRkMxNTc5ODdFRENBODRDRDZCRDk1NjlDNEVBMTc0RTVFOTQ2REM1M0QzNkZFMTlCMjI4ODZEMUUwRTAwQkNCIDIxIDEyMjQ2NDA5OERBMzIxREU3MkJENUM0OTVGRkIwRjcwQkQ3MTBBRDUxMUU5MjI4NUM1MEQ3QjNDNTE4MEQyMDkwIDYgNzkzRTI0MDNCMEU5QkM1Q0U4MTA0QkZGQkU3MUVCQ0NCRTFCRkNBMkI1MzkwQjg5MEMwQ0UwNDE4MjgxRERGMyA0IDFEMDU1QjI0RTc0MjZDOEI2QUU4Nzk4OEFENUREOTEwQTJFNTE0RTI1QkYzREM3RkFGNjRFMzc3QkIzQTJBMDIgNiA2MjFCMURBMEYyNTUwMTI4MjIxMTYwQjVBNjA3RDhENDJFNkMxNjk3RUY1MzhCMDg5MjM2NkM4QjExQjg0ODY3IDQgMTg3MTlBQjQxNDJBQkZEOTk3RkQ0RjcxNjJFQUM5MjhGRTdGQzQ4NUQ4MkE0Qjc4OUZBNzFBMTE5Qzc1RjVGNSJ9fV0sInRhaWxzIjp7InNpemUiOjg1LCJjdXJyZW50X2luZGV4IjowLCJnX2Rhc2giOiIxIDE4QUY1MThEMzVEMkMyMjMzQjVEODFCQTM0MjVDNjE3QzFGREE1RDk0RkNFRTVCNzgyMkZGNzI0MzE2QUNDNEYgMSAxRTlEQjlDNjc4NjZCMTdBQkMwODMxQjM2QTA4M0M5ODYzMkI1MjNFRThFNkFCRjVFM0Y1QzJDOTI3MDQwMEE4IDEgMTI2NjNEQ0RBQ0Y3Qjk2OTM5MDQxOTFDMkJCOEZCRDA3NDI3ODQ4MUZGRkNBMDc2OTVERDM5NEFGRkYxMkYwMSAxIDAyQzkwOTYwNjA4NkRGQzM1RkMxNzI0RjZDOTJFRDdFNDM5Njk1MzIwREY2RTM3MDdDODY2N0M3QTM0REJGNjYgMiAwOTVFNDVEREY0MTdEMDVGQjEwOTMzRkZDNjNENDc0NTQ4QjdGRkZGNzg4ODgwMkYwN0ZGRkZGRjdEMDdBOEE4IDEgMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsImdhbW1hIjoiMDdDMjgwMDg2QzU1MjZEOTU2M0UyQjA5QzdBOEQ4NEYxQzA4MTkzQkYyODk1NDE3RjYyMUU4Mzk4RjE4QjEzOSJ9LCJyZXZvY2F0aW9uUHVibGljS2V5Ijp7InoiOiIxIDEyQTIxRkM3MzQ3QUIzQUM3NzRCNDdGRTNGQzA1MTM4MUJBNzc1REE4OUVDQ0VEQ0M5OEQ1QjgyMEExNTI1ODEgMSAxNDA5QzUyMzg3NEEyRjEwMDNBNEVGM0JFOUJGQkM2NDIzNENDQjFDNzM2Mjk4M0U5RDk3MEE2RTg5MTAxMEI3IDEgMUY5MzY0NzMxNzg4MEE5MERGNzRDNEE3QjU0NTcyRkJFMjRERkQzODY1RDg2MkFBNzZBMTEzMzBBMzkzRkJFNSAxIDE5MjZENzk3MzgzMDc1MEY1MjUyRDRFQkRCNzc2RkZBRTI4NEZDQThFMzc2NThCNEEwQjYxRjlDNUZENEM0M0QgMSAwNUY5OTUwODU1Njg1RkM5OTZEREE5QjIzOUI3RDg0RjQ4QkYwQ0NBN0M4NjU2REI5Q0I4QTY2NDlDQjdBQjBGIDEgMDgwMzhBNEE2MjY1RkRFRDc1QUZBMEU1MzNFQUNCRDE3OUYxRjRGQzY0Q0U1Q0MyQkM5NDhCRTg3MDkxNjUyNSAxIDI0QTlFNTRFRTJFRTlDMUNENkVBMzVDQUE4NzU5MTM2QzU5NjEyMTIxNDg1NDVENTFFMUYxODdBOUM3NjY4MzUgMSAxREJENjQzMzY0MzA5MzdBNDdBQkFBQThEMkE3NTE3RTU2QTBGOEVBMTAxNTQxNDAyNUY3QjU2N0Y1Mzg3RjI3IDEgMTk1MTMxQjAyQUI3MDcyMUJERUZDOUVFNzAwMzlGN0EwMjY4MkZDNzhFM0UwOTk5RkQxMDI3QzVCQTk2NTFDQiAxIDI0MjQxQzMxNjg5NUNCMDU4QUUyMkQyQ0RCNTQ2NUUyNDRCQjY0RDhBNDAwRTVFRkEwNEFEOTg4MTdGM0M0MjIgMSAxRjgxRTIyQkYzQjlCQUU0OTY2MkE5MEMzMjA1RUNDQkI3QThBNEQ4ODc2RkFCMjk0QkRENzc5OTI4MkJDNDNGIDEgMTU2MUNCN0E5QURFREZDM0JDRDZCQjAxQUU5MzlBRDhERDBBQUQ3MEZBMjlDOTc2NjhBMjU0RjFFRThDRjk0QyJ9LCJtYXhpbXVtQ3JlZGVudGlhbENvdW50Ijo0Mn0sImlzcyI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4OTY3MGY3OTc0ZTcwMjFlNDk0MGM1NmQ0N2Y2YjMxZmRmZGQzN2RlOCJ9.u5zqvHGpJba1t591_WrPLZm417HyjKZqLV892rDIdvcGcp4R7cd36BjV9nvIf3cmCbS1AmkMqP1PS74md2KP0QA"
    }
  }
}

async function workflow_create_creds_setup() {
  /*const schema = await createSchema(
    {
      name: "TestSchema",
      description: "TestDesc",
      properties,
      requiredProperties,
      publicKeyDidId: issuerDID + '#key1',
      privateKeyDidId: issuerPK,
      identity: issuerDID
    },
    {
      identity: issuerDID.replace('0x', ''),
      privateKey: issuerPK
    }
  )*/

  /*const cred_def = await createCredentialDefinition(
    {
      schemaId: TEST_SCHEMA_ID,
      issuerDid: issuerDID,
      publicKeyDidId: issuerDID + '#key1',
      privateKeyDidId: issuerPK,
    },
    {
      identity: issuerDID.replace('0x', ''),
      privateKey: issuerPK
    }
  )*/

  /*const rev_reg = await createRevocationRegistry({
    credentialDefinitionId: TEST_CRED_DEF.definition.id,
    maxCredentialCount: 42,
    publicKeyDidId: issuerDID + '#key1',
    privateKeyDidId: issuerPK,
  },
  {
    identity: issuerDID.replace('0x', ''),
    privateKey: issuerPK
  })*/

  console.dir(JSON.stringify(rev_reg))
}

async function workflow_self_issue_credential() {
  const ms = createMasterSecret();

  const proposal = await createCredentialProposal({
    schemaId: TEST_SCHEMA_ID,
    issuerDid: issuerDID,
    subjectDid: issuerDID
  });

  const offer = await createCredentialOffer({
    proposal,
    credentialDefinitionId: TEST_CRED_DEF.definition.id
  });

  const request = await createCredentialRequest({
    offer,
    credentialDefinition: TEST_CRED_DEF.definition,
    masterSecret: ms,
    credentialValues: {
      eigenschaft1: "wololo"
    }
  });
  console.dir(request)
  const credential = await issueCredential({
    credentialDefinition: TEST_CRED_DEF.definition,
    credentialDefinitionKey: TEST_CRED_DEF.definitionKey,
    credentialRequest: request.request,
    revocationRegistryKey: TEST_REV_REG.privateKey,
    revocationRegistryInfo: TEST_REV_REG.revocationInfo,
    revocationRegistryDefinition: TEST_REV_REG.revocationRegistryDefinition,
    blindingFactors: request.blindingFactors,
    masterSecret: ms,
    issuerDid: issuerDID,
    subjectDid: issuerDID
  })

  console.dir(credential);
  console.log(JSON.stringify(credential.credential));


  const proof = await requestProof({
    schemaId: TEST_SCHEMA_ID,
    issuerDid: issuerDID,
    proverDid: issuerDID,
    revealedAttributes:['eigenschaft1']
  })

  console.dir(proof)

  const presentedProof = await presentProof({
    proofRequest: proof,
    credentialDefinition: TEST_CRED_DEF.definition,
    credential: credential.credential,
    schema: TEST_SCHEMA,
    revocationRegistryDefinition: TEST_REV_REG.revocationRegistryDefinition,
    revocationWitness: credential.revocationState.witness,
    masterSecret: ms
  })

  console.dir(JSON.stringify(presentedProof))

  const verifiedProof = await verifyProof({
    proof: presentedProof,
    proofRequest: proof,
    credentialDefinition: TEST_CRED_DEF.definition,
    schema: TEST_SCHEMA,
    revocationRegistryDefinition: TEST_REV_REG.revocationRegistryDefinition
  })

  console.dir(verifiedProof)
}

workflow_self_issue_credential()

/*wasm.create_schema(
  issuerDID,
  "my_test_schema",
  "Cool test schema",
  JSON.stringify(properties),
  JSON.stringify(requiredProperties),
  issuerDID,
  issuerPK,
  issuerPK,
  issuerIdentity
).then(async res => {

  console.warn("------ CREATED SCHEMA");
  const schema = JSON.parse(res);
  console.dir(schema);

  const did = await wasm.get_did("13.69.59.185", schema.id);
  console.warn("------ RESOLVED DID " + schema.id);
  console.dir(did);
})*/

/*wasm.create_schema().then(async res => {
  const schema = JSON.parse(res);

  const cred_def = await wasm.create_credential_definition(schema.id);
  const cred_def_parsed = JSON.parse(cred_def);
  console.dir(cred_def_parsed);
  const proof = await wasm.request_proof(schema.id);
  const ms = wasm.create_master_secret();
  const proposal = await wasm.create_credential_proposal(schema.id);
  const offer = await wasm.create_credential_offer(proposal,cred_def_parsed[0].id);
  const request = await wasm.create_credential_request(JSON.stringify(cred_def_parsed[0]), offer, ms);
  const request_parsed = JSON.parse(request);
  const rev_reg = await wasm.create_revocation_registry_definition(cred_def_parsed[0].id, 42);
  console.log('---------------------------------')
  console.dir(JSON.parse(rev_reg));
  const rev_reg_parsed = JSON.parse(rev_reg);
  const iss_cred = await wasm.issue_credential(
    JSON.stringify(cred_def_parsed[0]),
    JSON.stringify(cred_def_parsed[1]),
    JSON.stringify(request_parsed[0]), 
    JSON.stringify(rev_reg_parsed.privateKey),
    JSON.stringify(rev_reg_parsed.revocationInfo),
    JSON.stringify(rev_reg_parsed.revocationRegistryDefinition),
    JSON.stringify(request_parsed[1]),
    ms
  );
  
  const iss_cred_parsed = JSON.parse(iss_cred);

  const present_proof = await wasm.present_proof(
    proof,
    JSON.stringify(iss_cred_parsed.credential),
    JSON.stringify(cred_def_parsed[0]),
    JSON.stringify(schema),
    JSON.stringify(rev_reg_parsed.revocationRegistryDefinition),
    ms
  );

  const verify_proof = await wasm.verify_proof(
    present_proof,
    proof,
    JSON.stringify(cred_def_parsed[0]),
    JSON.stringify(schema),
    JSON.stringify(rev_reg_parsed.revocationRegistryDefinition),
  )


/*
  let schema: CredentialSchema = create_credential_schema(&mut vade).await?;
  let (definition, credential_private_key) = create_credential_definition(&mut vade, &schema).await?;
  let proof_request: ProofRequest = request_proof(&mut vade, &schema).await?;
  let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();
  let proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
  let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal, &definition).await?;
  let (request, blinding_factors) = create_credential_request(&mut vade, &definition, &offer, &master_secret).await?;


  //let (revocation_registry_definition, revocation_key_private, revocation_info):
  //(RevocationRegistryDefinition, RevocationKeyPrivate, RevocationIdInformation)
  let rev_reg_def: CreateRevocationRegistryDefinitionResult
      = create_revocation_registry_definition(&mut vade, &definition, 42).await?;
  let (mut credential, _): (Credential, _) = issue_credential(
      &mut vade, &definition,
      &credential_private_key,
      &request,
      &rev_reg_def.private_key,
      &rev_reg_def.revocation_info,
      &rev_reg_def.revocation_registry_definition
  ).await?;

  Prover::post_process_credential_signature(
    &mut credential,
    &request,
    &definition,
    blinding_factors,
    &master_secret,
    &rev_reg_def.revocation_registry_definition
  );

  let presented_proof: ProofPresentation = present_proof(
      &mut vade,
      &proof_request,
      &credential,
      &definition,
      &schema,
      &rev_reg_def.revocation_registry_definition,
      &master_secret,
  ).await?;

  // run test
  let result: ProofVerification = verify_proof(
      &mut vade,
      &presented_proof,
      &proof_request,
      &definition,
      &schema,
      &rev_reg_def.revocation_registry_definition
  ).await?;
  println!("{}", serde_json::to_string(&result).unwrap());
  console.dir(cred_def);
  console.dir(proof)
})*/