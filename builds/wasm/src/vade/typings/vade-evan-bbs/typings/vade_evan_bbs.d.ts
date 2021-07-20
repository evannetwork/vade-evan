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
  BbsCredential,
  BbsCredentialOffer,
  BbsCredentialRequest,
  BbsProofRequest,
  CredentialProposal,
  CredentialSubject,
  ProofPresentation,
  SchemaProperty,
  UnfinishedBbsCredential,
} from './application/datatypes';

/** Message passed to vade containing the desired credential type.
* Does not perform action if type does not indicate credential type BBS+.
* This can be done by passing "bbs" as the value for "type". */
export interface TypeOptions {
  type?: string,
}

/** Contains information necessary to make on-chain transactions (e.g. updating a DID Document). */
export interface AuthenticationOptions {
  /** Reference to the private key, will be forwarded to external signer if available */
  privateKey: string,
  /** DID of the identity */
  identity: string,
}

/** API payload needed to create a revocation list */
export interface CreateRevocationListPayload {
  /** DID of the issuer */
  issuerDid: string,
  /** DID of the issuer's public key used to verify the credential's signature */
  issuerPublicKeyDid: string,
  /** Private key of the issuer used to sign the credential */
  issuerProvingKey: string,
}

/** API payload for issuing a new credential
* Currently needs both an unsigned verifiable credential containing all the data
* and the nquad representation of this verifiable credential.  */
export interface IssueCredentialPayload {
  /** The VC to sign, without any appended proof */
  unsignedVc: Partial<BbsCredential>,
  /** Nquads representation of the VC without any appended proof */
  nquads: string[],
  /** DID url of the public key of the issuer used to later verify the signature */
  issuerPublicKeyId: string,
  /** The public bbs+ key of the issuer used to later verify the signature */
  issuerPublicKey: string,
  /** The secret bbs+ key used to create the signature */
  issuerSecretKey: string,
  /** Credential request */
  credentialRequest: BbsCredentialRequest,
  /** Credential offer linked to the credential request */
  credentialOffer: BbsCredentialOffer,
  /** Indices of nquads to be marked as requiredRevealStatements in the credential */
  requiredIndices: number[],
}

/** API payload for creating a BbsCredentialOffer to be sent by an issuer.
* Contains information about how many messages the final credential will hold. */
export interface OfferCredentialPayload {
  /** DID of the issuer */
  issuer: string,
  /** Proposal that precedes the offer */
  credentialProposal: CredentialProposal,
  /** Number of total nquads in the final credential */
  nquadCount: number,
}

/** API payload for creating a zero-knowledge proof out of a BBS+ signature. */
export interface PresentProofPayload {
  /** The proof request sent by a verifier */
  proofRequest: BbsProofRequest,
  /** All relevant credentials references via the requested credential schema ID */
  credentialSchemaMap: Record<string, BbsCredential>,
  /** Properties to be revealed for each credential by schema ID */
  revealedPropertiesSchemaMap: Record<string, CredentialSubject>,
  /** Public key per credential by schema ID */
  publicKeySchemaMap: Record<string, string>,
  /** The respective nquads by respective credential's schema ID */
  nquadsSchemaMap: Record<string, string[]>,
  /** Prover's master secret */
  masterSecret: string,
  /** DID of the prover */
  proverDid: string,
  /** Key DID of the prover's public key for the created assertion proof */
  proverPublicKeyDid: string,
  /** Prover's secret key to create an assertion proof with */
  proverProvingKey: string,
}

/** API payload to create a credential proposal to be sent by a holder. */
export interface CreateCredentialProposalPayload {
  /** DID of the issuer */
  issuer: string,
  /** DID of the subject */
  subject: string,
  /** DID of a credential schema to propose */
  schema: string,
}

/** API payload to create a credential request to be sent by a holder as a response
* to a BbsCredentialOffer. */
export interface RequestCredentialPayload {
  /** Credential offering sent by an issuer */
  credentialOffering: BbsCredentialOffer,
  /** Master secret of the holder/receiver */
  masterSecret: string,
  /** Cleartext values to be signed in the credential */
  credentialValues: Record<string, string>,
  /** Public key of the issuer */
  issuerPubKey: string,
}

/** API payload to create a BbsProofRequest to be sent by a verifier. */
export interface RequestProofPayload {
  /** DID of the verifier */
  verifierDid: string,
  /** List of schema IDs to request */
  schemas: string[],
  /** Attributes to reveal per schema ID */
  revealAttributes: Record<string, number[]>,
}

/** API payload to revoke a credential as this credential's issuer. */
export interface RevokeCredentialPayload {
  /** DID of the issuer */
  issuer: string,
  /** DID of the revocation list credential */
  revocationList: string,
  /** Credential ID to revoke */
  revocationId: string,
  /** DID of the issuer's public key for verifying assertion proofs */
  issuerPublicKeyDid: string,
  /** DID of the issuer's secret key for creating assertion proofs */
  issuerProvingKey: string,
}

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

/** API payload for finishing a UnfinishedBbsCredential as a holder.   */
export interface FinishCredentialPayload {
  /** Credential with blind signature to finish */
  credential: UnfinishedBbsCredential,
  /** Holder's master secret */
  masterSecret: string,
  /** Signed values of the credential's signature */
  nquads: string[],
  /** Issuer's BBS+ public key */
  issuerPublicKey: string,
  /** Blinding created during credential request creation */
  blinding: string,
}

/** API payload for verifying a received proof as a verifer. */
export interface VerifyProofPayload {
  /** BBS+ Presentation to verify */
  presentation: ProofPresentation,
  /** Proof request sent by verifier */
  proofRequest: BbsProofRequest,
  /** Relevant BBS+ public keys for each credential schema occuring in this proof */
  keysToSchemaMap: Record<string, string>,
  /** Signer address */
  signerAddress: string,
}

/** API payload to create new BBS+ keys and persist them on the DID document. */
export interface CreateKeysPayload {
  keyOwnerDid: string,
}

/** Result of the createKeys method for BBS+ */
export interface BbsKeys {
  /** DID Url of the persisted public key */
  didUrl: string,
  publicKey: string,
  secretKey: string,
}
