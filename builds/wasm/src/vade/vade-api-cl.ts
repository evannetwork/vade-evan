/* eslint-disable import/no-extraneous-dependencies */
import {
  AuthenticationOptions,
  BigNumber,
  CreateCredentialDefinitionPayload,
  CreateCredentialDefinitionResult,
  CreateCredentialProposalPayload,
  CreateCredentialSchemaPayload,
  CreateRevocationRegistryDefinitionPayload,
  CreateRevocationRegistryDefinitionResult,
  Credential,
  CredentialDefinition,
  CredentialOffer,
  CredentialPrivateKey,
  CredentialProposal,
  CredentialRequest,
  CredentialSchema,
  CredentialSecretsBlindingFactors,
  FinishCredentialPayload,
  IssueCredentialPayload,
  IssueCredentialResult,
  MasterSecret,
  OfferCredentialPayload,
  PresentProofPayload,
  ProofPresentation,
  ProofRequest,
  ProofVerification,
  RequestCredentialPayload,
  RequestCredentialResult,
  RequestProofPayload,
  RevocationIdInformation,
  RevocationKeyPrivate,
  RevocationState,
  SchemaProperty,
  TypeOptions as ClTypeOptions,
  ValidateProofPayload,
  Witness,
} from './typings/vade-evan-cl';
import { checkRequiredProperties, VadeOptions, VadeApiShared } from './vade-api-shared';

export interface ClAuthenticationOptions extends AuthenticationOptions, ClTypeOptions {
  privateKey: string;
  identity: string;
}

const TYPE_CL = 'cl';
const TYPE_OPTIONS_CL = { type: TYPE_CL };

class VadeApiCl extends VadeApiShared {
  /**
   * creates a schema on substrate and returns it
   *
   * @param params parameters for the schema
   * @param params.identity issuer identity
   * @param params.name name of the schema
   * @param params.properties properties attached to the schema
   * @param params.properties.KEY KEY name of the property
   * @param params.properties.KEY.type type of the property (string, ...)
   * @param params.publicKeyDidId id string of the signed public key in did (e.g. did:evan:0x12345#key-1)
   * @param params.requiredProperties array of strings with required properties
   * @param params.description description of the schema
   * @param options options for vade
   * @param options.identity Substrate identity to use (e.g. did:evan:0x12345)
   * @param options.privateKey key to request the signing endpoint with
   */
  public async createSchema(
    params: {
      identity: string,
      name: string,
      properties: Record<string, SchemaProperty>,
      publicKeyDidId: string,
      requiredProperties: string[],
      description?: string,
    },
    options: VadeOptions,
  ): Promise<CredentialSchema> {
    checkRequiredProperties(
      params,
      [
        'name',
        'properties',
        'requiredProperties',
        'publicKeyDidId',
        'identity',
      ],
      'params',
    );

    checkRequiredProperties(
      options,
      ['privateKey'],
      'options',
    );

    if (options && options.identity && !options.identity.startsWith('did')) {
      throw new Error('identity should start with did:evan:...');
    }

    return this.executeVade<ClAuthenticationOptions, CreateCredentialSchemaPayload, CredentialSchema>(
      {
        command: 'vc_zkp_create_credential_schema',
        method: 'did:evan',
        options: {
          privateKey: options.privateKey,
          identity: options.identity,
          type: TYPE_CL,
        },
        payload: {
          issuer: params.identity,
          schemaName: params.name,
          description: params.description || '',
          properties: params.properties,
          requiredProperties: params.requiredProperties,
          allowAdditionalProperties: false,
          issuerPublicKeyDid: params.publicKeyDidId,
          issuerProvingKey: options.privateKey,
        },
      },
    );
  }

  /**
   * creates a credential definition on substrate and returns it
   *
   * @param params parameters for the schema
   * @param params.issuerDid did for the issuer (e.g. did:evan:0x12345)
   * @param params.pSafe safe prime number 1 for cred def
   * @param params.publicKeyDidId id string of the signed public key in did (e.g. did:evan:0x12345#key-1)
   * @param params.qSafe safe prime number 2 for cred def
   * @param params.schemaId id for the used schema
   * @param params.privateKey key to request the signing endpoint with
   * @param options options for vade
   * @param options.identity Substrate identity to use (e.g. did:evan:0x12345)
   * @param options.privateKey key to request the signing endpoint with
   */
  public async createCredentialDefinition(
    params: {
      issuerDid: string,
      pSafe: BigNumber,
      publicKeyDidId: string,
      qSafe: BigNumber,
      schemaId: string,
      privateKey: string,
    },
    options: VadeOptions,
  ): Promise<{
      definition: CredentialDefinition,
      definitionKey: CredentialPrivateKey,
    }> {
    checkRequiredProperties(
      params,
      [
        'schemaId',
        'publicKeyDidId',
        'privateKey',
        'pSafe',
        'qSafe',
        'issuerDid',
      ],
      'params',
    );
    checkRequiredProperties(
      options,
      ['privateKey'],
      'options',
    );

    if (options && options.identity && !options.identity.startsWith('did')) {
      throw new Error('identity should start with did:evan:...');
    }

    const [definition, definitionKey] = await this.executeVade<
    ClAuthenticationOptions,
    CreateCredentialDefinitionPayload,
    CreateCredentialDefinitionResult>(
      {
        command: 'vc_zkp_create_credential_definition',
        method: 'did:evan',
        options: {
          privateKey: options.privateKey,
          identity: options.identity,
          type: TYPE_CL,
        },
        payload: {
          schemaDid: params.schemaId,
          issuerDid: params.issuerDid,
          issuerPublicKeyDid: params.publicKeyDidId,
          issuerProvingKey: options.privateKey,
          pSafe: params.pSafe,
          qSafe: params.qSafe,
        },
      },
    );
    return { definition, definitionKey };
  }

  /**
   * creates a master secret for issuing credentials and presenting proofs
   */
  public async createMasterSecret(): Promise<MasterSecret> {
    return this.executeVade<ClTypeOptions, void, MasterSecret>(
      {
        command: 'run_custom_function',
        customFunction: 'create_master_secret',
        options: TYPE_OPTIONS_CL,
        method: null,
      },
    );
  }

  /**
   * creates a proof request from a given issuer and prover
   *
   * @param params parameters for the schema
   * @param params.proverDid did for the prover (e.g. did:evan:0x12346)
   * @param params.revealedAttributes array of strings with to be revealed attributes from the schema
   * @param params.schemaId id for the used schema
   * @param params.verifierDid did for the verifier (e.g. did:evan:0x12345)
   */
  public async requestProof(
    params: {
      proverDid: string,
      revealedAttributes: string[],
      schemaId: string,
      verifierDid: string,
    },
  ): Promise<ProofRequest> {
    checkRequiredProperties(
      params,
      [
        'schemaId',
        'verifierDid',
        'proverDid',
        'revealedAttributes',
      ],
      'params',
    );

    return this.executeVade<ClTypeOptions, RequestProofPayload, ProofRequest>(
      {
        command: 'vc_zkp_request_proof',
        method: 'did:evan',
        options: TYPE_OPTIONS_CL,
        payload: {
          verifierDid: params.verifierDid,
          proverDid: params.proverDid,
          subProofRequests: [{
            schema: params.schemaId,
            revealedAttributes: params.revealedAttributes,
          }],
        },
      },
    );
  }

  /**
   * creates a proposal for a credential for a given schema
   *
   * @param params parameters for the schema
   * @param params.issuerDid did for the issuer (e.g. did:evan:0x12345)
   * @param params.schemaId id for the used schema
   * @param params.subjectDid did for the subject (e.g. did:evan:0x12346)
   */
  public async createCredentialProposal(
    params: {
      issuerDid: string,
      schemaId: string,
      subjectDid: string,
    },
  ): Promise<CredentialProposal> {
    checkRequiredProperties(
      params,
      [
        'schemaId',
        'issuerDid',
        'subjectDid',
      ],
      'params',
    );

    return this.executeVade<ClTypeOptions, CreateCredentialProposalPayload, CredentialProposal>(
      {
        command: 'vc_zkp_create_credential_proposal',
        method: 'did:evan',
        options: TYPE_OPTIONS_CL,
        payload: {
          issuer: params.issuerDid,
          subject: params.subjectDid,
          schema: params.schemaId,
        },
      },
    );
  }

  /**
   * creates a offer for a credential for a given proposal
   *
   * @param params parameters for the offer
   * @param params.credentialDefinitionId id of the credential definition
   * @param params.proposal given credential proposal
   */
  public async createCredentialOffer(
    params: {
      credentialDefinitionId: string,
      proposal: CredentialProposal,
    },
  ): Promise<CredentialOffer> {
    checkRequiredProperties(
      params,
      [
        'proposal',
        'credentialDefinitionId',
      ],
      'params',
    );

    // eslint-disable-next-line no-param-reassign
    const payload = {
      ...params.proposal,
      credentialDefinition: params.credentialDefinitionId,
    } as OfferCredentialPayload;
    return this.executeVade<ClTypeOptions, OfferCredentialPayload, CredentialOffer>(
      {
        command: 'vc_zkp_create_credential_offer',
        method: 'did:evan',
        options: TYPE_OPTIONS_CL,
        payload,
      },
    );
  }

  /**
   * creates a request for a credential with given values
   *
   * @param params parameters for the request
   * @param params.credentialValues object with values from the schema
   * @param params.masterSecret master secret object
   * @param params.offer given credential offer
   */
  public async createCredentialRequest(
    params: {
      credentialValues: Record<string, string>,
      masterSecret: MasterSecret,
      offer: CredentialOffer,
    },
  ): Promise<{
      request: CredentialRequest,
      blindingFactors: CredentialSecretsBlindingFactors,
    }> {
    checkRequiredProperties(
      params,
      [
        'offer',
        'masterSecret',
        'credentialValues',
      ],
      'params',
    );

    const [request, blindingFactors] = await this.executeVade<
    ClTypeOptions, RequestCredentialPayload, RequestCredentialResult>(
      {
        command: 'vc_zkp_request_credential',
        method: 'did:evan',
        options: TYPE_OPTIONS_CL,
        payload: {
          credentialOffering: params.offer,
          credentialSchema: params.offer.schema,
          masterSecret: params.masterSecret,
          credentialValues: params.credentialValues,
        },
      },
    );

    return { request, blindingFactors };
  }

  /**
   * creates a revocation registry for a given credential definition
   *
   * @param params parameters for the revocation registry
   * @param params.credentialDefinitionId credential definition object
   * @param params.maxCredentialCount given credential offer
   * @param params.publicKeyDidId id string of the signed public key in did (e.g. did:evan:0x12345#key-1)
   * @param options options for vade
   * @param options.identity Substrate identity to use (e.g. did:evan:0x12345)
   * @param options.privateKey key to request the signing endpoint with
   */
  public async createRevocationRegistry(
    params: {
      credentialDefinitionId: string,
      maxCredentialCount: number,
      publicKeyDidId: string,
    },
    options: VadeOptions,
  ): Promise<CreateRevocationRegistryDefinitionResult> {
    checkRequiredProperties(
      params,
      [
        'credentialDefinitionId',
        'maxCredentialCount',
        'publicKeyDidId',
      ],
      'params',
    );
    checkRequiredProperties(
      options,
      [
        'privateKey',
      ],
      'options',
    );
    if (options && options.identity && !options.identity.startsWith('did')) {
      throw new Error('identity should start with did:evan:...');
    }

    return this.executeVade<
    ClAuthenticationOptions,
    CreateRevocationRegistryDefinitionPayload,
    CreateRevocationRegistryDefinitionResult>(
      {
        command: 'vc_zkp_create_revocation_registry_definition',
        method: 'did:evan',
        options: {
          privateKey: options.privateKey,
          identity: options.identity,
          type: TYPE_CL,
        },
        payload: {
          credentialDefinition: params.credentialDefinitionId,
          issuerPublicKeyDid: params.publicKeyDidId,
          issuerProvingKey: options.privateKey,
          maximumCredentialCount: params.maxCredentialCount,
        },
      },
    );
  }

  /**
   * issues a credential for a given definition for a given subject
   *
   * @param params parameters for the revocation registry
   * @param params.credentialDefinitionKey credential definition key object
   * @param params.credentialRequest credential request object
   * @param params.revocationRegistryDefinitionDid revocation registry definition object
   * @param params.revocationRegistryInfo revocation registry info object
   * @param params.revocationRegistryKey revocation registry key object
   * @param params.issuerDid did of the issuer (e.g. did:evan:0x12345)
   * @param params.subjectDid did of the subject (e.g. did:evan:0x12346)
   */
  public async issueCredential(
    params: {
      credentialDefinitionKey: CredentialPrivateKey,
      credentialRequest: CredentialRequest,
      issuerDid: string,
      revocationRegistryDefinitionDid: string,
      revocationRegistryInfo: RevocationIdInformation,
      revocationRegistryKey: RevocationKeyPrivate,
      subjectDid: string,
    },
  ): Promise<IssueCredentialResult> {
    checkRequiredProperties(
      params,
      [
        'credentialDefinitionKey',
        'credentialRequest',
        'revocationRegistryKey',
        'revocationRegistryInfo',
        'revocationRegistryDefinitionDid',
        'issuerDid',
        'subjectDid',
      ],
      'params',
    );

    return this.executeVade<ClTypeOptions, IssueCredentialPayload, IssueCredentialResult>(
      {
        command: 'vc_zkp_issue_credential',
        method: 'did:evan',
        options: TYPE_OPTIONS_CL,
        payload: {
          issuer: params.issuerDid,
          subject: params.subjectDid,
          credentialRequest: params.credentialRequest,
          credentialPrivateKey: params.credentialDefinitionKey,
          credentialRevocationDefinition: params.revocationRegistryDefinitionDid,
          revocationPrivateKey: params.revocationRegistryKey,
          revocationInformation: params.revocationRegistryInfo,
        },
      },
    );
  }

  /**
   * Finish (postprocess) credential.
   *
   * @param params.blindingFactors blinding factors to use
   * @param params.credential credential to finish
   * @param params.credentialRequest credential request of credential
   * @param params.credentialRevocationDefinition revocation definition did
   * @param params.masterSecret master secret used to post processing
   * @param params.revocationState credentials revocation state
   */
  public async finishCredential(
    params: {
      blindingFactors: CredentialSecretsBlindingFactors,
      credential: Credential,
      credentialRequest: CredentialRequest,
      credentialRevocationDefinition: string,
      masterSecret: MasterSecret,
      revocationState: RevocationState,
    },
  ): Promise<Credential> {
    checkRequiredProperties(
      params,
      [
        'credential',
        'credentialRequest',
        'credentialRevocationDefinition',
        'blindingFactors',
        'masterSecret',
        'revocationState',
      ],
      'params',
    );

    return this.executeVade<ClTypeOptions, FinishCredentialPayload, Credential>(
      {
        command: 'vc_zkp_finish_credential',
        method: 'did:evan',
        options: TYPE_OPTIONS_CL,
        payload: {
          credential: params.credential,
          credentialRequest: params.credentialRequest,
          credentialRevocationDefinition: params.credentialRevocationDefinition,
          blindingFactors: params.blindingFactors,
          masterSecret: params.masterSecret,
          revocationState: params.revocationState,
        },
      },
    );
  }

  /**
   * Creates a proof presentation for a given proof request and credential.
   *
   * @param params parameters for the revocation registry
   * @param params.credential credential request object
   * @param params.masterSecret master secret object
   * @param params.proofRequest credential definition object
   * @param params.revocationWitness revocation registry definition object
   */
  public async presentProof(
    params: {
      credential: Credential,
      masterSecret: MasterSecret,
      proofRequest: ProofRequest,
      revocationWitness: Witness,
    },
  ): Promise<ProofPresentation> {
    checkRequiredProperties(
      params,
      [
        'proofRequest',
        'credential',
        'revocationWitness',
        'masterSecret',
      ],
      'params',
    );

    const credentials = {
      [params.proofRequest.subProofRequests[0].schema]: params.credential,
    };
    const witnesses = {
      [params.credential.id]: params.revocationWitness,
    };
    return this.executeVade<ClTypeOptions, PresentProofPayload, ProofPresentation>(
      {
        command: 'vc_zkp_present_proof',
        method: 'did:evan',
        options: TYPE_OPTIONS_CL,
        payload: {
          proofRequest: params.proofRequest,
          credentials,
          witnesses,
          masterSecret: params.masterSecret,
        },
      },
    );
  }

  /**
   * Verifies a proof against a given proof request.
   *
   * @param params parameters for the revocation registry
   * @param params.proof credential definition object
   * @param params.proofRequest credential definition object
   */
  public async verifyProof(
    params: {
      proof: ProofPresentation,
      proofRequest: ProofRequest,
    },
  ): Promise<boolean> {
    checkRequiredProperties(
      params,
      [
        'proof',
        'proofRequest',
      ],
      'params',
    );

    const verifiedProof = await this.executeVade<ClTypeOptions, ValidateProofPayload, ProofVerification>(
      {
        command: 'vc_zkp_verify_proof',
        method: 'did:evan',
        options: TYPE_OPTIONS_CL,
        payload: {
          presentedProof: params.proof,
          proofRequest: params.proofRequest,
        },
      },
    );

    return verifiedProof.status === 'verified';
  }

  /**
   * generates a safe prime for credential definitions
   */
  public async generateSafePrime(): Promise<BigNumber> {
    return this.executeVade<void, void, BigNumber>(
      {
        command: 'run_custom_function',
        customFunction: 'generate_safe_prime',
        method: null,
      },
    );
  }

  // eslint-disable-next-line @typescript-eslint/naming-convention
  public async workflow_self_issue_credential(
    issuerDid: string,
    subjectDid: string,
    schemaDid: string,
    definitionDid: string,
    definitionKey: string,
    revDefDid: string,
    revRegInfo: RevocationIdInformation,
    revRegPk: RevocationKeyPrivate,
    ms: MasterSecret,
    values: Record<string, string>,
  ): Promise<IssueCredentialResult> {
    const proposal = await this.createCredentialProposal({
      schemaId: schemaDid,
      issuerDid,
      subjectDid,
    });

    const offer = await this.createCredentialOffer({
      proposal,
      credentialDefinitionId: definitionDid,
    });

    const request = await this.createCredentialRequest({
      offer,
      masterSecret: ms,
      credentialValues: values,
    });

    const credential = await this.issueCredential({
      credentialDefinitionKey: definitionKey,
      credentialRequest: request.request,
      revocationRegistryKey: revRegPk,
      revocationRegistryInfo: revRegInfo,
      revocationRegistryDefinitionDid: revDefDid,
      issuerDid,
      subjectDid,
    });

    credential.credential = await this.finishCredential({
      credential: credential.credential,
      credentialRequest: request.request,
      credentialRevocationDefinition: revDefDid,
      blindingFactors: request.blindingFactors,
      masterSecret: ms,
      revocationState: credential.revocationState,
    });

    return credential;
  }

  // eslint-disable-next-line @typescript-eslint/naming-convention
  public async workflow_present_proof(
    schemaId: string,
    credential: Credential,
    revocationState: RevocationState,
    ms: MasterSecret,
    revealedAttributes: string[],
    verifierDid: string,
    proverDid: string,
  ): Promise<{
      presentedProof: ProofPresentation,
      proofRequest: ProofRequest,
    }> {
    const proof = await this.requestProof({
      schemaId,
      verifierDid,
      proverDid,
      revealedAttributes,
    });

    const presentedProof = await this.presentProof({
      proofRequest: proof,
      credential,
      revocationWitness: revocationState.witness,
      masterSecret: ms,
    });

    return {
      presentedProof,
      proofRequest: proof,
    };
  }
}

export {
  VadeApiCl,
};
