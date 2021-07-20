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

// use empty placeholder for external types
// there should usually be no need to work with them directly, as they can be passed
// to vade api and returned without interaction with their inner data

export interface BigNumber {}
export interface BlindedCredentialSecrets {}
export interface BlindedCredentialSecretsCorrectnessProof {}
export interface CredentialKeyCorrectnessProof {}
export interface CredentialPrivateKey {}
export interface CredentialPublicKey {}
export interface CredentialSecretsBlindingFactors {}
export interface CryptoCredentialSignature {}
export interface MasterSecret {}
export interface Nonce {}
export interface RevocationKeyPrivate {}
export interface RevocationKeyPublic {}
export interface RevocationRegistry {}
export interface RevocationRegistryDelta {}
export interface RevocationTailsGenerator {}
export interface SignatureCorrectnessProof {}
export interface Witness {}
