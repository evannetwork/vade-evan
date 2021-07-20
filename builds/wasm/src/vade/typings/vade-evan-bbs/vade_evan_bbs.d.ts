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
  UnsignedCredential,
} from './application/datatypes';

export interface TypeOptions {
  type?: string,
}

export interface AuthenticationOptions {
  privateKey: string,
  identity: string,
}

export interface CreateRevocationListPayload {
  issuerDid: string,
  issuerPublicKeyDid: string,
  issuerProvingKey: string,
}

// ####### Please keep until nquads is available in Rust #######
// export interface IssueCredentialPayload {
//   issuer: string,
//   issuerPublicKeyId: string,
//   issuerPublicKey: string,
//   issuerSecretKey: string,
//   subject: string,
//   schema: string,
//   credentialRequest: BbsCredentialRequest,
//   credentialOffer: BbsCredentialOffer,
//   requiredIndices: number[],
//   nquads: string[],
//   revocationListDid: string,
//   revocationListId: string,
// }

export interface IssueCredentialPayload {
  unsignedVc: UnsignedCredential,
  nquads: string[],
  issuerPublicKeyId: string,
  issuerPublicKey: string,
  issuerSecretKey: string,
  credentialRequest: BbsCredentialRequest,
  credentialOffer: BbsCredentialOffer,
  requiredIndices: number[],
}

export interface OfferCredentialPayload {
  issuer: string,
  credentialProposal: CredentialProposal,
  nquadCount: number,
}

export interface PresentProofPayload {
  proofRequest: BbsProofRequest,
  credentialSchemaMap: Record<string, BbsCredential>,
  revealedPropertiesSchemaMap: Record<string, CredentialSubject>,
  publicKeySchemaMap: Record<string, string>,
  nquadsSchemaMap: Record<string, string[]>,
  masterSecret: string,
  proverDid: string,
  proverPublicKeyDid: string,
  proverProvingKey: string,
}

export interface CreateCredentialProposalPayload {
  issuer: string,
  subject: string,
  schema: string,
}

export interface RequestCredentialPayload {
  credentialOffering: BbsCredentialOffer,
  masterSecret: string,
  credentialValues: Record<string, string>,
  issuerPubKey: string,
}

export interface RequestProofPayload {
  verifierDid: string,
  schemas: string[],
  revealAttributes: Record<string, number[]>,
}

export interface RevokeCredentialPayload {
  issuer: string,
  revocationList: string,
  revocationId: string,
  issuerPublicKeyDid: string,
  issuerProvingKey: string,
}

export interface CreateCredentialSchemaPayload {
  issuer: string,
  schemaName: string,
  description: string,
  properties: Record<string, SchemaProperty>,
  requiredProperties: string[],
  allowAdditionalProperties: boolean,
  issuerPublicKeyDid: string,
  issuerProvingKey: string,
}

export interface FinishCredentialPayload {
  credential: UnfinishedBbsCredential,
  masterSecret: string,
  nquads: string[],
  issuerPublicKey: string,
  blinding: string,
}

export interface VerifyProofPayload {
  presentation: ProofPresentation,
  proofRequest: BbsProofRequest,
  keysToSchemaMap: Record<string, string>,
  signerAddress: string,
  nquadsToSchemaMap: Record<string, string[]>
}

export interface CreateKeysPayload {
  keyOwnerDid: string,
}

export interface BbsKeys {
  didUrl: string,
  publicKey: string,
  secretKey: string,
}
