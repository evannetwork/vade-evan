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

import { AssertionProof } from '../crypto/crypto_datatypes';
import {
  BlindedCredentialSecrets,
  BlindedCredentialSecretsCorrectnessProof,
  CredentialKeyCorrectnessProof,
  CredentialPublicKey,
  CryptoCredentialSignature,
  Nonce,
  RevocationKeyPublic,
  RevocationRegistry,
  RevocationRegistryDelta,
  RevocationTailsGenerator,
  SignatureCorrectnessProof,
  Witness,
} from '../external';

/**
 * Holds metadata and the key material used to issue and process credentials,
 * and create and verify proofs.
 * Needs to be stored publicly available and temper-proof.
 */
export interface CredentialDefinition {
  id: string,
  type: string,
  issuer: string,
  schema: string,
  createdAt: string,
  publicKey: CredentialPublicKey,
  publicKeyCorrectnessProof: CredentialKeyCorrectnessProof,
  proof?: AssertionProof,
}

/**
 * Specifies the properties of a credential, as well as metadata.
 * Needs to be stored publicly available and temper-proof.
 */
export interface CredentialSchema {
  id: string,
  type: string,
  name: string,
  author: string,
  createdAt: string,
  description: string,
  properties: Record<string, SchemaProperty>,
  required: string[],
  additionalProperties: boolean,
  proof?: AssertionProof,
}

export interface SchemaProperty {
  type: string,
  format?: string,
  items?: string[],
}

/**
 * Message following a `CredentialProposal`, sent by an issuer.
 * Specifies the DIDs of both the `CredentialSchema` and `CredentialDefinition`
 * to be used for issuance.
 */
export interface CredentialOffer {
  issuer: string,
  subject: string,
  type: string,
  schema: string,
  credentialDefinition: string,
  nonce: Nonce,
}

/**
 * Message following a `CredentialOffer`, sent by a potential credential prover.
 * Provides the values that need to be signed by the issuer in both encoded/cleartext, and blinded format.
 * Incorporates the nonce value sent in `CredentialOffer`.
 */
export interface CredentialRequest {
  subject: string,
  schema: string,
  credentialDefinition: string,
  type: string,
  blindedCredentialSecrets: BlindedCredentialSecrets,
  blindedCredentialSecretsCorrectnessProof: BlindedCredentialSecretsCorrectnessProof,
  credentialNonce: Nonce,
  credentialValues: Record<string, EncodedCredentialValue>,
}

export interface CredentialSignature {
  type: string,
  credentialDefinition: string,
  signature: CryptoCredentialSignature,
  signatureCorrectnessProof: SignatureCorrectnessProof,
  issuanceNonce: Nonce,
  revocationId: number,
  revocationRegistryDefinition: string,
}

export interface CredentialSchemaReference {
  id: string,
  type: string,
}

export interface CredentialSubject {
  id: string,
  data: Record<string, EncodedCredentialValue>,
}

/**
 * A verifiable credential issued by an issuer upon receiving a `CredentialRequest`.
 * Specifies the signed values, the DID of the prover/subject, the `CredentialSchema`, and the `CredentialSignature`
 * including revocation info
 */
export interface Credential {
  '@context': string[],
  id: string,
  type: string[],
  issuer: string,
  issuanceDate: string,
  credentialSubject: CredentialSubject,
  credentialSchema: CredentialSchemaReference,
  proof: CredentialSignature,
}

/**
 * Contains all necessary cryptographic information for credential revocation.
 * The `registry` and `registryDelta` properties need to be updated after every revocation
 * (and, depending on the type of the revocation registry, after every issuance).
 * Contains a `DeltaHistory` to let provers update their credential's `Witness` before proving non-revocation.
 * Needs to be stored publicly available and temper-proof.
 */
export interface RevocationRegistryDefinition {
  id: string,
  credentialDefinition: string,
  updatedAt: string,
  registry: RevocationRegistry,
  registryDelta: RevocationRegistryDelta,
  deltaHistory: DeltaHistory[],
  tails: RevocationTailsGenerator,
  revocationPublicKey: RevocationKeyPublic,
  maximumCredentialCount: number,
  proof?: AssertionProof,
}

export interface DeltaHistory {
  created: number,
  delta: RevocationRegistryDelta,
}

/**
 * Holds the current `Witness` for a credential. Witnesses need to be updated before creating proofs.
 * To do this, the prover needs to retrieve the `DeltaHistory` of the relevant `RevocationRegistryDefinition`
 * and update the witness with all deltas that are newer than the `updated` property of the `RevocationState`.
 */
export interface RevocationState {
  credentialId: string,
  revocationId: number,
  updated: number,
  delta: RevocationRegistryDelta,
  witness: Witness,
}

/**
 * Message to initiate credential issuance, sent by (potential) prover.
 * Specifies the schema to be used for the credential.
 */
export interface CredentialProposal {
  issuer: string,
  subject: string,
  type: string,
  schema: string,
}

export interface SubProofRequest {
  schema: string,
  revealedAttributes: string[],
}

/**
 * Message sent by a verifier to prompt a prover to prove one or many assertions.
 */
export interface ProofRequest {
  verifier: string,
  prover: string,
  createdAt: string,
  nonce: Nonce,
  subProofRequests: SubProofRequest[],
}

export interface CredentialSubProof {
  credentialDefinition: string,
  revocationRegistryDefinition: string,
  proof: string,
}

export interface AggregatedProof {
  nonce: Nonce,
  aggregatedProof: string,
}

/**
 * A single proof of a schema requested in a `ProofRequest` that reveals the requested attributes.
 */
export interface ProofCredential {
  '@context': string[],
  id: string,
  type: string[],
  issuer: string,
  issuanceDate: string,
  credentialSubject: CredentialSubject,
  credentialSchema: CredentialSchemaReference,
  proof: CredentialSubProof,
}

/**
 * A collection of all proofs requested in a `ProofRequest`. Sent to a verifier as the response to
 * a `ProofRequest`.
 */
export interface ProofPresentation {
  '@context': string[],
  id: string,
  type: string[],
  verifiableCredential: ProofCredential[],
  proof: AggregatedProof,
}

export interface ProofVerification {
  presentedProof: string,
  status: string,
  reason?: string,
}

export interface EncodedCredentialValue {
  raw: string,
  encoded: string,
}

export interface RevocationIdInformation {
  definitionId: string,
  nextUnusedId: number,
  usedIds: number[],
}
