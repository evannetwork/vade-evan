import {
  CredentialBbs,
  CredentialSchema,
  CredentialOfferBbs,
  CredentialRequestBbs,
  ProofRequestBbs,
  CredentialProposalBbs,
  RevocationListCredential,
  UnfinishedCredentialBbs,
  UnsignedCredentialBbs,
} from './typings';
import { Vade } from './vade';

function keyOf(did: string) {
  return `${did}#key-1`;
}

// const CREDENTIAL_OFFER_TYPE = 'EvanBbsCredentialOffering';
const CREDENTIAL_PROOF_PURPOSE = 'assertionMethod';
const CREDENTIAL_PROPOSAL_TYPE = 'EvanCredentialProposal';
const CREDENTIAL_REQUEST_TYPE = 'EvanBbsCredentialRequest';
const CREDENTIAL_SIGNATURE_TYPE = 'BbsBlsSignature2020';
const CREDENTIAL_PROOF_TYPE = 'BbsBlsSignatureProof2020';
const HOLDER_DID = 'did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403901';
const ISSUER_DID = 'did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6';
const MASTER_SECRET = 'OASkVMA8q6b3qJuabvgaN9K1mKoqptCv4SCNvRmnWuI=';
const NQUADS = ['test_property_string: value'];
const PUB_KEY = 'jCv7l26izalfcsFe6j/IqtVlDolo2Y3lNld7xOG63GjSNHBVWrvZQe2O859q9JeVEV4yXtfYofGQSWrMVfgH5ySbuHpQj4fSgLu4xXyFgMidUO1sIe0NHRcXpOorP01o';
const REMOTE_ISSUER_DID = 'did:evan:testcore:0x3fd50CC762DC91F5440B8a530Db7B52813730596'.toLocaleLowerCase();
const REMOTE_SIGNING_KEY = '270f69319fb71423d5f66f2a9d5f828536fa3c6108807449d4a541911b566b68';
const REMOTE_SIGNING_OPTIONS = {
  signingKey: REMOTE_SIGNING_KEY,
  identity: REMOTE_ISSUER_DID,
};
const SCHEMA_DID = 'did:evan:zkp:0xd641c26161e769cef4b41760211972b274a8f37f135a34083e4e48b3f1035eda';
const SECRET_KEY = 'Ilm14JX/ULRybFcHOq93gzDu5McYuX9L7AE052Sz5SQ=';
const SIGNER_1_ADDRESS = '0x03c174bfc6d05f2f520e6ada156d0a5120aebdee';
const SUBJECT_DID = 'did:evan:schema:0x1ace8b01be3bca9ba4a1462130a1e0ad0d2f539f';
const TEST_CREDENTIAL_VALUES = { test_property_string: 'value' };
const VERIFIER_DID = 'did:evan:testcore:0x1234512345123451234512345123451234512345';

const vade = new Vade({ signer: 'local' });

const helper = {
  createCredentialProposal: () => vade.bbs.createCredentialProposal(
    {
      issuer: ISSUER_DID,
      schema: SCHEMA_DID,
      subject: SUBJECT_DID,
    },
  ),
  createCredentialOffer: (proposal: CredentialProposalBbs) => vade.bbs.createCredentialOffer(
    {
      issuer: proposal.issuer,
      nquadCount: NQUADS.length,
      subject: proposal.subject,
    },
  ),
  createCredentialRequest: (offer: CredentialOfferBbs, schema: CredentialSchema) => vade.bbs.createCredentialRequest(
    {
      credentialOffering: offer,
      masterSecret: MASTER_SECRET,
      credentialValues: TEST_CREDENTIAL_VALUES,
      issuerPubKey: PUB_KEY,
      credentialSchema: schema,
    },
  ),
  createRevocationRegistry: (credentialDid) => vade.bbs.createRevocationRegistry(
    {
      credentialDid: credentialDid.id,
      issuerDid: REMOTE_ISSUER_DID,
      issuerPublicKeyDid: keyOf(REMOTE_ISSUER_DID),
      issuerProvingKey: REMOTE_SIGNING_OPTIONS.signingKey,
    },
    REMOTE_SIGNING_OPTIONS,
  ),
  createBbsKeys: () => vade.bbs.createBbsKeys(
    { keyOwnerDid: REMOTE_ISSUER_DID },
    REMOTE_SIGNING_OPTIONS,
  ),
  issueCredential: async ({
    offer,
    request,
    unsignedVc,
  }: {
    offer: CredentialOfferBbs,
    request: CredentialRequestBbs,
    unsignedVc: UnsignedCredentialBbs
  }) => vade.bbs.issueCredential(
    {
      unsignedVc,
      issuerPublicKeyId: keyOf(ISSUER_DID),
      issuerPublicKey: PUB_KEY,
      issuerSecretKey: SECRET_KEY,
      credentialRequest: request,
      credentialOffer: offer,
      requiredIndices: [1],
      nquads: NQUADS,
    },
  ),
  finishCredential: ({
    unfinishedCredential,
    signatureBlinding,
  }: {
    unfinishedCredential: UnfinishedCredentialBbs,
    signatureBlinding: string,
  }) => vade.bbs.finishCredential(
    {
      credential: unfinishedCredential,
      masterSecret: MASTER_SECRET,
      nquads: NQUADS,
      issuerPublicKey: PUB_KEY,
      blinding: signatureBlinding,
    },
  ),
  presentProof: ({
    finishedCredential,
    proofRequest,
  }: {
    finishedCredential: CredentialBbs,
    proofRequest: ProofRequestBbs,
  }) => vade.bbs.presentProof(
    {
      proofRequest,
      credentialSchemaMap: { [SCHEMA_DID]: finishedCredential },
      revealedPropertiesSchemaMap: {
        [SCHEMA_DID]: {
          id: HOLDER_DID,
          data: finishedCredential.credentialSubject.data,
        },
      },
      publicKeySchemaMap: { [SCHEMA_DID]: PUB_KEY },
      nquadsSchemaMap: { [SCHEMA_DID]: NQUADS },
      masterSecret: MASTER_SECRET,
      proverDid: VERIFIER_DID,
      proverPublicKeyDid: keyOf(VERIFIER_DID),
      proverProvingKey: REMOTE_SIGNING_KEY,
    },
    REMOTE_SIGNING_OPTIONS,
  ),
  requestProof: () => vade.bbs.requestProof(
    {
      verifierDid: VERIFIER_DID,
      schemas: [SCHEMA_DID],
      revealAttributes: { [SCHEMA_DID]: [1] },
    },
  ),
  verifyProof: ({
    presentation, proofRequest, nquads, revocationList,
  }) => vade.bbs.verifyProof(
    {
      presentation,
      proofRequest,
      keysToSchemaMap: { [SCHEMA_DID]: PUB_KEY },
      nquadsToSchemaMap: { [SCHEMA_DID]: nquads },
      signerAddress: SIGNER_1_ADDRESS,
      revocationList,
    },
  ),
  revokeCredential: ({ revocationList }) => vade.bbs.revokeCredential(
    {
      issuer: ISSUER_DID,
      revocationList: revocationList.id,
      revocationId: '0',
      issuerPublicKeyDid: keyOf(REMOTE_ISSUER_DID),
      issuerProvingKey: REMOTE_SIGNING_OPTIONS.signingKey,
    },
    REMOTE_SIGNING_OPTIONS,
  ),
  getUnsignedVc: (subject, revocationList) => ({
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://schema.org',
      'https://w3id.org/vc-revocation-list-2020/v1',
    ],
    id: 'uuid:any',
    type: ['VerifiableCredential'],
    issuer: ISSUER_DID,
    credentialSubject: {
      id: subject,
      data: TEST_CREDENTIAL_VALUES,
    },
    credentialSchema: {
      id: SCHEMA_DID,
      type: 'EvanZKPSchema',
    },
    issuanceDate: (new Date()).toISOString(),
    credentialStatus: {
      id: `${revocationList.id}#0`,
      type: 'RevocationList2020Status',
      revocationListIndex: '0',
      revocationListCredential: revocationList.id,
    },
  }),
};

describe('vade API for BBS+ credentials', () => {
  jest.setTimeout(300_000);
  let revocationListPromise: Promise<RevocationListCredential>;

  beforeAll(async () => {
    // initially create revocation registry did
    const didDoc = await vade.sdid.createDid(null, null, null, null);
    // const didDocument = await vade.sdid.getDid(didDoc.did.didDocument.id);
    revocationListPromise = Promise.resolve(await helper.createRevocationRegistry(didDoc.did.didDocument));
  });

  it('can create BBS+ keypair', async () => {
    const oldDidDocument = await vade.did.getDid(REMOTE_ISSUER_DID);
    await helper.createBbsKeys();
    const newDidDocument = await vade.did.getDid(REMOTE_ISSUER_DID);
    const oldDidDocumentWithoutPubKey = {
      ...oldDidDocument,
      assertionMethod: null,
    };
    const newDidDocumentWithoutPubKey = {
      ...newDidDocument,
      assertionMethod: null,
    };

    expect(newDidDocumentWithoutPubKey).toEqual(oldDidDocumentWithoutPubKey);
    const oldAssertionCount = oldDidDocument?.assertionMethod?.length || 0;
    expect(newDidDocument.assertionMethod).toHaveLength(oldAssertionCount + 1);
    expect(newDidDocument.assertionMethod.pop()).toBeTruthy();
    expect(newDidDocument.assertionMethod).toEqual(oldDidDocument.assertionMethod);
  });

  it('can create a credential proposal', async () => {
    const proposal = await helper.createCredentialProposal();

    expect(proposal.subject).toEqual(SUBJECT_DID);
    expect(proposal.issuer).toEqual(ISSUER_DID);
    expect(proposal.schema).toEqual(SCHEMA_DID);
    expect(proposal.type).toEqual(CREDENTIAL_PROPOSAL_TYPE);
  });

  it('can create credential offer with proposal', async () => {
    const proposal = await helper.createCredentialProposal();
    const offer = await helper.createCredentialOffer(proposal);

    expect(offer.issuer).toEqual(ISSUER_DID);
    expect(offer.subject).toEqual(proposal.subject);
  });

  it('can create credential request', async () => {
    const proposal = await helper.createCredentialProposal();
    const offer = await helper.createCredentialOffer(proposal);
    const schema = await vade.did.getDid(SCHEMA_DID) as unknown as CredentialSchema;
    const { credentialRequest: request, signatureBlinding } = await helper.createCredentialRequest(offer, schema);

    expect(request.schema).toEqual(SCHEMA_DID);
    expect(request.subject).toEqual(offer.subject);
    expect(request.type).toEqual(CREDENTIAL_REQUEST_TYPE);
    expect(signatureBlinding).toBeTruthy();
  });

  it('can create revocation lists', async () => {
    const revocationList = await revocationListPromise;

    expect(revocationList).toEqual({
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/vc-revocation-list-2020/v1',
      ],
      id: expect.any(String),
      type: ['VerifiableCredential', 'RevocationList2020Credential'],
      issuer: keyOf(REMOTE_ISSUER_DID),
      issued: expect.any(String),
      credentialSubject: {
        id: expect.any(String),
        type: 'RevocationList2020',
        encodedList: expect.any(String),
      },
      proof: {
        type: 'EcdsaPublicKeySecp256k1',
        created: expect.any(String),
        proofPurpose: 'assertionMethod',
        verificationMethod: keyOf(REMOTE_ISSUER_DID),
        jws: expect.any(String),
      },
    });
  });

  it('can create unfinished credential', async () => {
    const proposal = await helper.createCredentialProposal();
    const offer = await helper.createCredentialOffer(proposal);
    const schema = await vade.did.getDid(SCHEMA_DID) as unknown as CredentialSchema;
    const { credentialRequest: request } = await helper.createCredentialRequest(offer, schema);
    const revocationList = await revocationListPromise;
    const unsignedVc = helper.getUnsignedVc(offer.subject, revocationList);
    const unfinishedCredential = await helper.issueCredential({ offer, request, unsignedVc });

    expect(unfinishedCredential).toEqual({
      ...unsignedVc,
      proof: {
        type: CREDENTIAL_SIGNATURE_TYPE,
        created: expect.any(String),
        proofPurpose: CREDENTIAL_PROOF_PURPOSE,
        verificationMethod: keyOf(ISSUER_DID),
        requiredRevealStatements: [1],
        credentialMessageCount: 2,
        blindSignature: expect.any(String),
      },
    });
  });

  it('can create finished credential', async () => {
    const proposal = await helper.createCredentialProposal();
    const offer = await helper.createCredentialOffer(proposal);
    const schema = await vade.did.getDid(SCHEMA_DID) as unknown as CredentialSchema;
    const {
      credentialRequest: request,
      signatureBlinding,
    } = await helper.createCredentialRequest(offer, schema);
    const revocationList = await revocationListPromise;
    const unsignedVc = helper.getUnsignedVc(offer.subject, revocationList);
    const unfinishedCredential = await helper.issueCredential({ offer, request, unsignedVc });
    const finishedCredential = await helper.finishCredential(
      { unfinishedCredential, signatureBlinding },
    );

    expect(finishedCredential.issuer).toEqual(ISSUER_DID);
    expect(finishedCredential.credentialSubject.id).toEqual(SUBJECT_DID);
    expect(finishedCredential.credentialSchema.id).toEqual(SCHEMA_DID);
    expect(finishedCredential.proof.requiredRevealStatements).toEqual([1]);
    expect(finishedCredential.proof.type).toEqual(CREDENTIAL_SIGNATURE_TYPE);
    expect(finishedCredential.proof.proofPurpose).toEqual(CREDENTIAL_PROOF_PURPOSE);
    expect(finishedCredential.proof.verificationMethod).toEqual(keyOf(ISSUER_DID));
    expect(finishedCredential.credentialSubject.data).toEqual(TEST_CREDENTIAL_VALUES);
    expect(Buffer.from(finishedCredential.proof.signature, 'base64').toString('base64'))
      .toEqual(finishedCredential.proof.signature);
  });

  it('request a proof', async () => {
    const proofRequest = await helper.requestProof();

    expect(proofRequest).toEqual({
      verifier: VERIFIER_DID,
      createdAt: expect.any(String),
      nonce: expect.any(String),
      type: 'BBS',
      subProofRequests: [
        {
          schema: SCHEMA_DID,
          revealedAttributes: [1],
        },
      ],
    });
  });

  it('create a presentation of a finished credential', async () => {
    const proposal = await helper.createCredentialProposal();
    const offer = await helper.createCredentialOffer(proposal);
    const schema = await vade.did.getDid(SCHEMA_DID) as unknown as CredentialSchema;
    const {
      credentialRequest: request,
      signatureBlinding,
    } = await helper.createCredentialRequest(offer, schema);
    const revocationList = await revocationListPromise;
    const unsignedVc = helper.getUnsignedVc(offer.subject, revocationList);
    const unfinishedCredential = await helper.issueCredential({ offer, request, unsignedVc });
    const finishedCredential = await helper.finishCredential(
      { unfinishedCredential, signatureBlinding },
    );
    const proofRequest = await helper.requestProof();
    const presentation = await helper.presentProof({ finishedCredential, proofRequest });

    expect(presentation).toEqual({
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://schema.org',
        'https://w3id.org/vc-revocation-list-2020/v1',
      ],
      id: expect.any(String),
      type: ['VerifiablePresentation'],
      verifiableCredential: [
        {
          ...finishedCredential,
          credentialSubject: {
            id: 'did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403901',
            data: { test_property_string: 'value' },
          },
          proof: {
            type: CREDENTIAL_PROOF_TYPE,
            created: expect.any(String),
            proofPurpose: CREDENTIAL_PROOF_PURPOSE,
            verificationMethod: keyOf(ISSUER_DID),
            credentialMessageCount: 2,
            nonce: expect.any(String),
            proof: expect.any(String),
          },
          issuanceDate: expect.anything(), // will not have `issuanceDate`, therefore overwrite it
        },
      ],
      proof: {
        type: 'EcdsaPublicKeySecp256k1',
        created: expect.any(String),
        proofPurpose: CREDENTIAL_PROOF_PURPOSE,
        verificationMethod: keyOf(VERIFIER_DID),
        jws: expect.any(String),
      },
    });
  });

  it('can verify a credential', async () => {
    const proposal = await helper.createCredentialProposal();
    const offer = await helper.createCredentialOffer(proposal);
    const schema = await vade.did.getDid(SCHEMA_DID) as unknown as CredentialSchema;
    const {
      credentialRequest: request,
      signatureBlinding,
    } = await helper.createCredentialRequest(offer, schema);
    const revocationList = await revocationListPromise;
    const unsignedVc = helper.getUnsignedVc(offer.subject, revocationList);
    const unfinishedCredential = await helper.issueCredential({ offer, request, unsignedVc });
    const finishedCredential = await helper.finishCredential(
      { unfinishedCredential, signatureBlinding },
    );
    const proofRequest = await helper.requestProof();
    const presentation = await helper.presentProof({ finishedCredential, proofRequest });
    const isValid = await helper.verifyProof({
      presentation, proofRequest, nquads: [NQUADS[0]], revocationList,
    });

    expect(isValid).toEqual({ presentedProof: presentation.id, status: 'verified' });
  });

  it('cannot verify a credential with wrong proven credentials', async () => {
    const proposal = await helper.createCredentialProposal();
    const offer = await helper.createCredentialOffer(proposal);
    const schema = await vade.did.getDid(SCHEMA_DID) as unknown as CredentialSchema;
    const {
      credentialRequest: request,
      signatureBlinding,
    } = await helper.createCredentialRequest(offer, schema);
    const revocationList = await revocationListPromise;
    const unsignedVc = helper.getUnsignedVc(offer.subject, revocationList);
    const unfinishedCredential = await helper.issueCredential({ offer, request, unsignedVc });
    const finishedCredential = await helper.finishCredential(
      { unfinishedCredential, signatureBlinding },
    );
    const proofRequest = await helper.requestProof();
    const presentation = await helper.presentProof({ finishedCredential, proofRequest });
    const isValid = await helper.verifyProof({
      presentation, proofRequest, nquads: ['We expect something different'], revocationList,
    });

    expect(isValid).toEqual({
      presentedProof: presentation.id,
      reason: 'Revealed message invalid for expected nquad: "We expect something different"',
      status: 'rejected',
    });
  });

  it('cannot verify revoked credential', async () => {
    const proposal = await helper.createCredentialProposal();
    const offer = await helper.createCredentialOffer(proposal);
    const schema = await vade.did.getDid(SCHEMA_DID) as unknown as CredentialSchema;
    const {
      credentialRequest: request,
      signatureBlinding,
    } = await helper.createCredentialRequest(offer, schema);
    const revocationList = await revocationListPromise;
    const unsignedVc = helper.getUnsignedVc(offer.subject, revocationList);
    const unfinishedCredential = await helper.issueCredential({ offer, request, unsignedVc });
    const finishedCredential = await helper.finishCredential(
      { unfinishedCredential, signatureBlinding },
    );
    const updatedRevocationList = await helper.revokeCredential({ revocationList });

    expect(updatedRevocationList).not.toEqual(revocationList);

    const proofRequest = await helper.requestProof();
    const presentation = await helper.presentProof({ finishedCredential, proofRequest });
    const isValid = await helper.verifyProof({
      presentation, proofRequest, nquads: [NQUADS[0]], revocationList,
    });

    expect(isValid).toEqual({
      presentedProof: presentation.id,
      reason: `Credential id ${presentation.verifiableCredential[0].id} is revoked`,
      status: 'rejected',
    });
  });
});
