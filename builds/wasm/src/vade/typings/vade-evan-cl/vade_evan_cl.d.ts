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
  BigNumber,
  CredentialPrivateKey,
  CredentialSecretsBlindingFactors,
  MasterSecret,
  RevocationKeyPrivate,
  Witness,
} from './external';

export interface TypeOptions {
  type?: string,
}

export interface AuthenticationOptions {
  privateKey: string,
  identity: string,
}

export interface CreateCredentialDefinitionPayload {
  issuerDid: string,
  schemaDid: string,
  issuerPublicKeyDid: string,
  issuerProvingKey: string,
  pSafe?: BigNumber
  qSafe?: BigNumber,
}

export type CreateCredentialDefinitionResult = [CredentialDefinition, CredentialPrivateKey];

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

export interface CreateRevocationRegistryDefinitionPayload {
  credentialDefinition: string,
  issuerPublicKeyDid: string,
  issuerProvingKey: string,
  maximumCredentialCount: number,
}

export interface CreateRevocationRegistryDefinitionResult {
  privateKey: RevocationKeyPrivate,
  revocationInfo: RevocationIdInformation,
  revocationRegistryDefinition: RevocationRegistryDefinition,
}

export interface IssueCredentialPayload {
  issuer: string,
  issuanceDate?: string,
  subject: string,
  credentialRequest: CredentialRequest,
  credentialRevocationDefinition: string,
  credentialPrivateKey: CredentialPrivateKey,
  revocationPrivateKey: RevocationKeyPrivate,
  revocationInformation: RevocationIdInformation,
}

export interface FinishCredentialPayload {
  credential: Credential,
  credentialRequest: CredentialRequest,
  credentialRevocationDefinition: string,
  blindingFactors: CredentialSecretsBlindingFactors,
  masterSecret: MasterSecret,
  revocationState: RevocationState,
}

export interface IssueCredentialResult {
  credential: Credential,
  revocationInfo: RevocationIdInformation,
  revocationState: RevocationState,
}

export interface OfferCredentialPayload {
  issuer: string,
  subject: string,
  schema: string,
  credentialDefinition: string,
}

export interface PresentProofPayload {
  proofRequest: ProofRequest,
  credentials: Record<string, Credential>,
  witnesses: Record<string, Witness>,
  masterSecret: MasterSecret,
}

export interface CreateCredentialProposalPayload {
  issuer: string,
  subject: string,
  schema: string,
}

export interface RequestCredentialPayload {
  credentialOffering: CredentialOffer,
  credentialSchema: string,
  masterSecret: MasterSecret,
  credentialValues: Record<string, string>,
}

export type RequestCredentialResult = [CredentialRequest, CredentialSecretsBlindingFactors];

export interface RequestProofPayload {
  verifierDid: string,
  proverDid: string,
  subProofRequests: SubProofRequest[]
}

export interface RevokeCredentialPayload {
  issuer: string,
  revocationRegistryDefinition: string,
  credentialRevocationId: number,
  issuerPublicKeyDid: string,
  issuerProvingKey: string,
}

export interface ValidateProofPayload {
  presentedProof: ProofPresentation,
  proofRequest: ProofRequest,
}
