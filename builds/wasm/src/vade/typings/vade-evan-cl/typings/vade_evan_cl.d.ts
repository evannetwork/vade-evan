/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

import {
  Credential,
  CredentialDefinition,
  CredentialOffer,
  CredentialRequest,
  ProofPresentation,
  ProofRequest,
  RevocationIdInformation,
  RevocationRegistryDefinition,
  RevocationState,
  SchemaProperty,
  SubProofRequest,
} from './application/datatypes';
import {
  CredentialPrivateKey,
  CredentialSecretsBlindingFactors,
  MasterSecret,
  RevocationKeyPrivate,
  Witness,
} from './external';

/** Message passed to vade containing the desired credential type.
* Does not perform action if type does not indicate credential type CL.
* This can be done by passing "cl" as the value for "type".
*/
export interface TypeOptions {
  type?: string,
}

/** Contains information necessary to make on-chain transactions (e.g. updating a DID Document).
 */
export interface AuthenticationOptions {
  /** Reference to the private key, will be forwarded to external signer if available */
  privateKey: string,
  /** DID of the identity */
  identity: string,
}

/** API payload needed to create a credential definition needed for issuing credentials */
export interface CreateCredentialDefinitionPayload {
  /** DID of the definition issuer/owner */
  issuerDid: string,
  /** DID of the schema to issue the definition for */
  schemaDid: string,
  /** DID of the issuer's public key */
  issuerPublicKeyDid: string,
  /** Key to sign the credential definition */
  issuerProvingKey: string,
}

export type CreateCredentialDefinitionResult = [CredentialDefinition, CredentialPrivateKey];

/** API payload needed to create a credential schema needed for issuing credentials */
export interface CreateCredentialSchemaPayload {
  /** DID of the schema issuer/owner */
  issuer: string,
  /** Name given to the schema */
  schemaName: string,
  /** A text describing the schema's purpose */
  description: string,
  /** The properties the schema holds */
  properties: Record<string, SchemaProperty>,
  /** Names of required properties */
  requiredProperties: string[],
  /** Tells a verifier whether properties not found in the schema are to be deemed valid */
  allowAdditionalProperties: boolean,
  /** DID of the issuer's public key to validate the schema's assertion proof */
  issuerPublicKeyDid: string,
  /** Secret key to sign the schema with */
  issuerProvingKey: string,
}

/** API payload to create a revocation registry definition needed to revoke issued credentials */
export interface CreateRevocationRegistryDefinitionPayload {
  /** DID of the credential definition this revocation registry is linked to */
  credentialDefinition: string,
  /** DID of the issuer's public key to validate the registry's assertion proof */
  issuerPublicKeyDid: string,
  /** Secret key to sign the registry with */
  issuerProvingKey: string,
  /** Maximum numbers of credentials to be tracked by this registry */
  maximumCredentialCount: number,
}

/** Information about a created revocation registry definition */
export interface CreateRevocationRegistryDefinitionResult {
  /** Key needed to revoke credentials */
  privateKey: RevocationKeyPrivate,
  /** Keeps track of used credential IDs and which ID to use next */
  revocationInfo: RevocationIdInformation,
  /** Revocation data, needs to be persisted in a public space */
  revocationRegistryDefinition: RevocationRegistryDefinition,
}

/** API payload needed to issue a new credential */
export interface IssueCredentialPayload {
  /** DID of the credential issuer */
  issuer: string,
  /** Date of issuance */
  issuanceDate?: string,
  /** DID of the credential subject */
  subject: string,
  /** Credential request sent by the subject */
  credentialRequest: CredentialRequest,
  /** DID of the associated revocation definition */
  credentialRevocationDefinition: string,
  /** Key to create the credential signature */
  credentialPrivateKey: CredentialPrivateKey,
  /** Key to make this credential revokable */
  revocationPrivateKey: RevocationKeyPrivate,
  /** Tracker of current and next revocation IDs to use */
  revocationInformation: RevocationIdInformation,
}

/** API payload needed to finish a blinded credential signature by a holder/subject */
export interface FinishCredentialPayload {
  /** The issued credential */
  credential: Credential,
  /** The associated credential request */
  credentialRequest: CredentialRequest,
  /** DID of the revocation registry definition */
  credentialRevocationDefinition: string,
  /** Blinding factors created during credential request creation */
  blindingFactors: CredentialSecretsBlindingFactors,
  /** Master secret to incorporate into the signature */
  masterSecret: MasterSecret,
  /** Current revocation state of the credential */
  revocationState: RevocationState,
}

/** Result of a call to issue_credential */
export interface IssueCredentialResult {
  /** The issued credential */
  credential: Credential,
  /** Tracker of current and next revocation IDs to use */
  revocationInfo: RevocationIdInformation,
  /** Current revocation state of the credential */
  revocationState: RevocationState,
}

/** API payload for creating a credential offer as an issuer */
export interface OfferCredentialPayload {
  /** DID of the issuer */
  issuer: string,
  /** DID of the subject */
  subject: string,
  /** DID of the schema of the credential to be issued */
  schema: string,
  /** DID of the credential definition of the credential to be issued */
  credentialDefinition: string,
}

/** API payload for creating proofs */
export interface PresentProofPayload {
  /** Proof request sent by a verifier */
  proofRequest: ProofRequest,
  /** Map of credentials referenced by their schema DIDs for all of the requested credentials */
  credentials: Record<string, Credential>,
  /** All of the updated witnesses referenced by their associated credential's schema DID */
  witnesses: Record<string, Witness>,
  /** The holder's master secret */
  masterSecret: MasterSecret,
}

/** API payload for creating a credential proposal */
export interface CreateCredentialProposalPayload {
  /** DID of the issuer */
  issuer: string,
  /** DID of the subject */
  subject: string,
  /** DID of the schema */
  schema: string,
}

/** API payload for creating a credential request */
export interface RequestCredentialPayload {
  /** Credential offering received by an issuer */
  credentialOffering: CredentialOffer,
  /** DID of the schema */
  credentialSchema: string,
  /** The holder's master secret */
  masterSecret: MasterSecret,
  /** Key-value pairs to be signed in the credential */
  credentialValues: Record<string, string>,
}

export type RequestCredentialResult = [CredentialRequest, CredentialSecretsBlindingFactors];

/** API payload for creationg proof requests as a verifier */
export interface RequestProofPayload {
  /** DID of the verifier   */
  verifierDid: string,
  /** DID of the prover */
  proverDid: string,
  /** List of subproof requests, each requiring the proof of one credential signature */
  subProofRequests: SubProofRequest[]
}

/** API payload to revoke a credential */
export interface RevokeCredentialPayload {
  /** DID of the issuer */
  issuer: string,
  /** DID of the associated revocation registry definition */
  revocationRegistryDefinition: string,
  /** ID of the credential to be revoked */
  credentialRevocationId: number,
  /** DID of the issuer's public key to validate the registry's assertion proof */
  issuerPublicKeyDid: string,
  /** Secret key to sign the registry with */
  issuerProvingKey: string,
}

/** API payload to validate a received proof */
export interface ValidateProofPayload {
  /** Proof received by a holder/prover */
  presentedProof: ProofPresentation,
  /** Proof request that was sent to the holder/prover */
  proofRequest: ProofRequest,
}
