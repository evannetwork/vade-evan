import {
  BbsCredential as CredentialBbs,
  BbsCredentialOffer as CredentialOfferBbs,
  BbsCredentialRequest as CredentialRequestBbs,
  BbsPresentation as ProofCredentialBbs,
  BbsProofRequest as ProofRequestBbs,
  BbsSubProofRequest as SubProofRequestBbs,
  CredentialProposal as CredentialProposalBbs,
  CredentialSchema as CredentialSchemaBbs,
  ProofPresentation as ProofPresentationBbs,
  RevocationListCredential,
  SchemaProperty as SchemaPropertyBbs,
  UnfinishedBbsCredential as UnfinishedCredentialBbs,
  UnsignedCredential as UnsignedCredentialBbs,
} from './vade-evan-bbs';
import {
  BigNumber,
  CreateRevocationRegistryDefinitionResult,
  Credential as CredentialCl,
  CredentialDefinition as CredentialDefinitionCl,
  CredentialOffer as CredentialOfferCl,
  CredentialPrivateKey,
  CredentialProposal as CredentialProposalCl,
  CredentialRequest as CredentialRequestCl,
  CredentialSchema as CredentialSchemaCl,
  CredentialSecretsBlindingFactors,
  EncodedCredentialValue as EncodedCredentialValueCl,
  IssueCredentialResult as IssueCredentialResultCl,
  MasterSecret as MasterSecretCl,
  ProofCredential as ProofCredentialCl,
  ProofPresentation as ProofPresentationCl,
  ProofRequest as ProofRequestCl,
  RevocationIdInformation,
  SchemaProperty as SchemaPropertyCl,
  SubProofRequest as SubProofRequestCl,
} from './vade-evan-cl';

export interface IssueCredentialResultBbs {
  credential: UnfinishedCredentialBbs;
}

export interface RequestCredentialResultCl {
  request: CredentialRequestCl;
  blindingFactors?: CredentialSecretsBlindingFactors;
}

export interface RequestCredentialResultBbs {
  credentialRequest: CredentialRequestBbs;
  signatureBlinding?: string;
}

export type CreateRevocationRegistryResult = CreateRevocationRegistryDefinitionResult | RevocationListCredential;
export type Credential = CredentialCl | CredentialBbs;
export type CredentialOffer = CredentialOfferCl | CredentialOfferBbs;
export type CredentialProposal = CredentialProposalCl | CredentialProposalBbs;
export type CredentialSchema = CredentialSchemaCl | CredentialSchemaBbs;
export type EncodedCredentialValueBbs = string;
export type EncodedCredentialValue = EncodedCredentialValueCl | EncodedCredentialValueBbs;
export type IssueCredentialResult = IssueCredentialResultCl | IssueCredentialResultBbs;
export type MasterSecret = MasterSecretCl | MasterSecretBbs;
export type MasterSecretBbs = string;
export type ProofCredential = ProofCredentialCl | ProofCredentialBbs;
export type ProofPresentation = ProofPresentationCl | ProofPresentationBbs;
export type ProofRequest = ProofRequestCl | ProofRequestBbs;
export type RequestCredentialResult = RequestCredentialResultCl | RequestCredentialResultBbs;
export type SchemaProperty = SchemaPropertyCl | SchemaPropertyBbs;
export type SubProofRequest = SubProofRequestCl | SubProofRequestBbs;

export {
  BigNumber,
  CreateRevocationRegistryDefinitionResult,
  CredentialBbs,
  CredentialCl,
  CredentialDefinitionCl,
  CredentialOfferBbs,
  CredentialOfferCl,
  CredentialPrivateKey,
  CredentialProposalBbs,
  CredentialProposalCl,
  CredentialRequestBbs,
  CredentialRequestCl,
  CredentialSchemaBbs,
  CredentialSchemaCl,
  CredentialSecretsBlindingFactors,
  EncodedCredentialValueCl,
  IssueCredentialResultCl,
  MasterSecretCl,
  ProofPresentationBbs,
  ProofPresentationCl,
  ProofRequestBbs,
  ProofRequestCl,
  RevocationIdInformation,
  RevocationListCredential,
  SchemaPropertyBbs,
  SchemaPropertyCl,
  SubProofRequestCl,
  SubProofRequestBbs,
  UnfinishedCredentialBbs,
  UnsignedCredentialBbs,
};
