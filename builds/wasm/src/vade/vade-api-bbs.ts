// eslint-disable-next-line import/no-extraneous-dependencies
import {
  AuthenticationOptions,
  BbsCredential,
  BbsCredentialOffer,
  BbsCredentialRequest,
  BbsKeys,
  BbsProofRequest,
  BbsProofVerification,
  CreateCredentialProposalPayload,
  CreateCredentialSchemaPayload,
  CreateKeysPayload,
  CreateRevocationListPayload,
  CredentialProposal,
  CredentialSchema,
  FinishCredentialPayload,
  IssueCredentialPayload,
  OfferCredentialPayload,
  PresentProofPayload,
  ProofPresentation,
  RequestCredentialPayload,
  RequestProofPayload,
  RevocationListCredential,
  RevokeCredentialPayload,
  SchemaProperty,
  TypeOptions as BbsTypeOptions,
  UnfinishedBbsCredential,
  VerifyProofPayload,
} from './typings/vade-evan-bbs';
import { checkRequiredProperties, VadeApiShared, VadeOptions } from './vade-api-shared';

export interface BbsAuthenticationOptions extends AuthenticationOptions, BbsTypeOptions {
  privateKey: string;
  identity: string;
}

const TYPE_BBS = 'bbs';
const TYPE_OPTIONS_BBS = { type: TYPE_BBS };

class VadeApiBbs extends VadeApiShared {
  /**
   * creates a schema on substrate and returns it
   *
   * @param params.identity issuer identity
   * @param params.name name of the schema
   * @param params.properties properties attached to the schema
   * @param params.publicKeyDidId id string of the signed public key in did (e.g. did:evan:0x12345#key-1)
   * @param params.requiredProperties array of strings with required properties
   * @param options.identity Substrate identity to use (e.g. did:evan:0x12345)
   * @param options.privateKey key to request the signing endpoint with
   */
  /*
    params: {
    identity: string;
    name: string;
    properties: Record<string, SchemaProperty>;
    publicKeyDidId: string;
    requiredProperties: string[];
    description?: string;
    credentialDid: string;
  },
  options: VadeOptions,
  context: Context,
): Promise<CredentialSchema> {
  checkRequiredProperties(
    params,
    ['identity', 'name', 'properties', 'publicKeyDidId', 'requiredProperties', 'credentialDid'],
    'params',
  );

  checkRequiredProperties(options, ['signingKey'], 'options');

   */
  public async createSchema(
    params: {
      identity: string,
      name: string,
      properties: Record<string, SchemaProperty>,
      publicKeyDidId: string,
      requiredProperties: string[],
      description?: string,
      credentialDid: string,
    },
    options: VadeOptions,
  ): Promise<CredentialSchema> {
    checkRequiredProperties(
      params,
      [
        'identity',
        'name',
        'properties',
        'publicKeyDidId',
        'requiredProperties',
        'credentialDid',
      ],
      'params',
    );

    checkRequiredProperties(
      options,
      ['signingKey'],
      'options',
    );

    if (options && options.identity && !options.identity.startsWith('did')) {
      throw new Error('identity should start with did:evan:...');
    }

    return this.executeVade<BbsAuthenticationOptions, CreateCredentialSchemaPayload, CredentialSchema>(
      {
        command: 'vc_zkp',
        subcommand: 'create_credential_schema',
        method: 'did:evan',
        options: {
          privateKey: options.remoteSignerUrl ? params.publicKeyDidId : options.signingKey,
          identity: options.identity,
          type: TYPE_BBS,
        },
        payload: {
          issuer: params.identity,
          schemaName: params.name,
          description: params.description || '',
          properties: params.properties,
          requiredProperties: params.requiredProperties,
          allowAdditionalProperties: false,
          issuerPublicKeyDid: params.publicKeyDidId,
          issuerProvingKey: options.remoteSignerUrl ? params.publicKeyDidId : options.signingKey,
          credentialDid: params.credentialDid,
        },
        signer: options.remoteSignerUrl ? `remote|${options.remoteSignerUrl}` : undefined,
      },
    );
  }

  /**
   * creates a master secret for issuing credentials and presenting proofs
   */
  public async createMasterSecret(): Promise<string> {
    return this.executeVade<BbsTypeOptions, void, string>(
      {
        command: 'vc_zkp',
        subcommand: 'create_master_secret',
        options: TYPE_OPTIONS_BBS,
        signer: null,
        method: null,
      },
    );
  }

  /**
   * creates a new keypair for BBS+ based proofs
   *
   * @param params.keyOwnerDid did that will receive new public key
   * @param options.identity Substrate identity to use (e.g. did:evan:0x12345)
   * @param options.privateKey key to request the signing endpoint with
   */
  public async createBbsKeys(
    params: CreateKeysPayload,
    options: VadeOptions,
  ): Promise<BbsKeys> {
    checkRequiredProperties(
      params,
      [
        'keyOwnerDid',
      ],
      'params',
    );
    const ms = await this.executeVade<BbsAuthenticationOptions, CreateKeysPayload, BbsKeys>(
      {
        command: 'vc_zkp',
        subcommand: 'create_new_keys',
        method: null,
        options: {
          privateKey: options.remoteSignerUrl ? params.keyOwnerDid : options.signingKey,
          identity: options.identity,
          type: TYPE_BBS,
        },
        payload: params,
        signer: options.remoteSignerUrl ? `remote|${options.remoteSignerUrl}` : undefined,
      },
    );
    return ms;
  }

  /**
   * creates a proof request from a given issuer and prover
   *
   * @param params.verifierDid did of verifier
   * @param params.schemas array of schemas to be proofed
   * @param params.revealAttributes object of string to number array for revealed indices
   */
  public async requestProof(
    params: RequestProofPayload,
  ): Promise<BbsProofRequest> {
    checkRequiredProperties(
      params,
      [
        'schemas',
        'revealAttributes',
      ],
      'params',
    );

    return this.executeVade<BbsTypeOptions, RequestProofPayload, BbsProofRequest>(
      {
        command: 'vc_zkp',
        subcommand: 'request_proof',
        method: 'did:evan',
        options: TYPE_OPTIONS_BBS,
        payload: params,
      },
    );
  }

  /**
   * creates a proposal for a credential for a given schema
   *
   * @param params.issuer did for the issuer (e.g. did:evan:0x12345)
   * @param params.schema id for the used schema
   * @param params.subject did for the subject (e.g. did:evan:0x12346)
   */
  public async createCredentialProposal(
    params: CreateCredentialProposalPayload,
  ): Promise<CredentialProposal> {
    checkRequiredProperties(
      params,
      [
        'issuer',
        'schema',
      ],
      'params',
    );

    return this.executeVade<BbsTypeOptions, CreateCredentialProposalPayload, CredentialProposal>(
      {
        command: 'vc_zkp',
        subcommand: 'create_credential_proposal',
        method: 'did:evan',
        options: TYPE_OPTIONS_BBS,
        payload: params,
      },
    );
  }

  /**
   * creates an offer for a credential for a given proposal
   *
   * @param params.issuer issuer did
   * @param params.credentialProposal given credential proposal
   * @param params.nquadCount current nquad count of issuer
   */
  public async createCredentialOffer(
    params: OfferCredentialPayload,
  ): Promise<BbsCredentialOffer> {
    checkRequiredProperties(
      params,
      [
        'issuer',
        'nquadCount',
      ],
      'params',
    );

    return this.executeVade<BbsTypeOptions, OfferCredentialPayload, BbsCredentialOffer>(
      {
        command: 'vc_zkp',
        subcommand: 'create_credential_offer',
        method: 'did:evan',
        options: TYPE_OPTIONS_BBS,
        payload: params,
      },
    );
  }

  /**
   * creates a request for a credential with given values
   *
   * @param params.credentialOffering given credential offer
   * @param params.masterSecret master secret
   * @param params.credentialValues object with values from the schema
   * @param params.issuerPubKey public key of issuer
   */
  public async createCredentialRequest(
    params: RequestCredentialPayload,
  ): Promise<{ credentialRequest: BbsCredentialRequest, signatureBlinding: string }> {
    checkRequiredProperties(
      params,
      [
        'credentialOffering',
        'masterSecret',
        'credentialValues',
        'issuerPubKey',
      ],
      'params',
    );

    const [credentialRequest, signatureBlinding] = await this.executeVade<
    BbsTypeOptions,
    RequestCredentialPayload,
    [BbsCredentialRequest, string]>(
      {
        command: 'vc_zkp',
        subcommand: 'request_credential',
        method: 'did:evan',
        options: TYPE_OPTIONS_BBS,
        payload: params,
      },
    );

    return { credentialRequest, signatureBlinding };
  }

  /**
   * creates a revocation registry for a given credential definition
   *
   * @param params.issuerDid did of issuer
   * @param params.issuerPublicKeyDid reference to public key in issuer did document
   * @param params.issuerProvingKey proving key of issuer
   * @param options.identity Substrate identity to use (e.g. did:evan:0x12345)
   * @param options.privateKey key to request the signing endpoint with
   */
  public async createRevocationRegistry(
    params: CreateRevocationListPayload,
    options: VadeOptions,
  ): Promise<RevocationListCredential> {
    checkRequiredProperties(
      params,
      [
        'issuerDid',
        'issuerPublicKeyDid',
        'issuerProvingKey',
        'credentialDid',
      ],
      'params',
    );
    checkRequiredProperties(
      options,
      [
        'signingKey',
      ],
      'options',
    );
    if (options && options.identity && !options.identity.startsWith('did')) {
      throw new Error('identity should start with did:evan:...');
    }

    return this.executeVade<
    BbsAuthenticationOptions,
    CreateRevocationListPayload,
    RevocationListCredential>(
      {
        command: 'vc_zkp',
        subcommand: 'create_revocation_registry_definition',
        method: 'did:evan',
        options: {
          privateKey: options.remoteSignerUrl ? params.issuerDid : options.signingKey,
          identity: options.identity,
          type: TYPE_BBS,
        },
        payload: params,
        signer: options.remoteSignerUrl ? `remote|${options.remoteSignerUrl}` : undefined,
      },
    );
  }

  /**
   * issues a credential for a given definition for a given subject
   *
   * @param params.unsignedVc unsigned credential
   * @param params.nquads credential nquad data
   * @param params.issuerPublicKeyId reference to public key in issuers did document
   * @param params.issuerPublicKey public key of issuer
   * @param params.issuerSecretKey secret key of issuer
   * @param params.credentialRequest credential request for which credential should be issued
   * @param params.credentialOffer credential offer for which credential should be issued
   * @param params.requiredIndices indices of required properties
   */
  public async issueCredential(
    params: IssueCredentialPayload,
  ): Promise<UnfinishedBbsCredential> {
    checkRequiredProperties(
      params,
      [
        'unsignedVc',
        'nquads',
        'issuerPublicKeyId',
        'issuerPublicKey',
        'issuerSecretKey',
        'credentialRequest',
        'credentialOffer',
        'requiredIndices',
      ],
      'params',
    );

    return this.executeVade<BbsTypeOptions, IssueCredentialPayload, UnfinishedBbsCredential>(
      {
        command: 'vc_zkp',
        subcommand: 'issue_credential',
        method: 'did:evan',
        options: TYPE_OPTIONS_BBS,
        payload: params,
      },
    );
  }

  /**
   * Finish (postprocess) credential.
   *
   * @param params.credential credential to finish
   * @param params.masterSecret master secret used to post processing
   * @param params.nquads credential nquad data
   * @param params.issuerPublicKey public key of issuer
   * @param params.blinding blinding to use
   */
  public async finishCredential(
    params: FinishCredentialPayload,
  ): Promise<BbsCredential> {
    checkRequiredProperties(
      params,
      [
        'credential',
        'masterSecret',
        'nquads',
        'issuerPublicKey',
        'blinding',
      ],
      'params',
    );

    return this.executeVade<BbsTypeOptions, FinishCredentialPayload, BbsCredential>(
      {
        command: 'vc_zkp',
        subcommand: 'finish_credential',
        method: 'did:evan',
        options: TYPE_OPTIONS_BBS,
        payload: params,
      },
    );
  }

  /**
   * Creates a proof presentation for a given proof request and credential.
   *
   * @param params.proofRequest related proof request
   * @param params.credentialSchemaMap credentials per schema
   * @param params.revealedPropertiesSchemaMap revealed properties per schema
   * @param params.publicKeySchemaMap public keys per schema
   * @param params.nquadsSchemaMap nquad data per schema
   * @param params.masterSecret master secret
   * @param params.proverDid did of prover
   * @param params.proverPublicKeyDid reference to public key in provers did document
   * @param params.proverProvingKey proving key to use
   * @param options.identity Substrate identity to use (e.g. did:evan:0x12345)
   * @param options.privateKey key to request the signing endpoint with
   */
  public async presentProof(
    params: PresentProofPayload,
    options: VadeOptions,
  ): Promise<ProofPresentation> {
    checkRequiredProperties(
      params,
      [
        'proofRequest',
        'credentialSchemaMap',
        'revealedPropertiesSchemaMap',
        'publicKeySchemaMap',
        'nquadsSchemaMap',
        'masterSecret',
        'proverDid',
        'proverPublicKeyDid',
        'proverProvingKey',
      ],
      'params',
    );

    return this.executeVade<BbsAuthenticationOptions, PresentProofPayload, ProofPresentation>(
      {
        command: 'vc_zkp',
        subcommand: 'present_proof',
        method: 'did:evan',
        options: {
          privateKey: options.signingKey,
          identity: options.identity,
          type: TYPE_BBS,
        },
        payload: params,
      },
    );
  }

  /**
   * Verifies a proof against a given proof request.
   *
   * @param params.presentation presentation to verify
   * @param params.proofRequest proof request for presentation
   * @param params.keysToSchemaMap keys per schema
   * @param params.signerAddress address of signer
   */
  public async verifyProof(
    params: VerifyProofPayload,
  ): Promise<BbsProofVerification> {
    checkRequiredProperties(
      params,
      [
        'presentation',
        'proofRequest',
        'keysToSchemaMap',
        'signerAddress',
      ],
      'params',
    );

    return this.executeVade<BbsTypeOptions, VerifyProofPayload, BbsProofVerification>(
      {
        command: 'vc_zkp',
        subcommand: 'verify_proof',
        method: 'did:evan',
        options: TYPE_OPTIONS_BBS,
        payload: params,
      },
    );
  }

  /**
   * revokes a given credential id in a revocation list
   *
   * @param params.issuer issuer did
   * @param params.revocationList stringified revocation list credential
   * @param params.revocationId id in the list which should be revoked
   * @param params.issuerPublicKeyDid did with id mentioned in the revocation list proof
   * @param params.issuerProvingKey uuid of the azure private key
   * @param options.identity Substrate identity to use (e.g. did:evan:0x12345)
   * @param options.privateKey key to request the signing endpoint with
   */
  public async revokeCredential(
    params: RevokeCredentialPayload,
    options: VadeOptions,
  ): Promise<RevocationListCredential> {
    checkRequiredProperties(
      params,
      [
        'issuer',
        'revocationList',
        'revocationId',
        'issuerPublicKeyDid',
        'issuerProvingKey',
      ],
      'params',
    );

    checkRequiredProperties(
      options,
      ['signingKey'],
      'options',
    );

    if (options && options.identity && !options.identity.startsWith('did')) {
      throw new Error('identity should start with did:evan:...');
    }

    return this.executeVade<BbsAuthenticationOptions, RevokeCredentialPayload, RevocationListCredential>(
      {
        command: 'vc_zkp',
        subcommand: 'revoke_credential',
        method: 'did:evan',
        options: {
          privateKey: options.signingKey,
          identity: options.identity,
          type: TYPE_BBS,
        },
        payload: params,
        signer: options.remoteSignerUrl ? `remote|${options.remoteSignerUrl}` : undefined,
      },
    );
  }
}

export {
  VadeApiBbs,
};
