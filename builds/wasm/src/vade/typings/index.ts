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
  AssertionProof as AssertionProofJwt,
  Credential as CredentialJwt,
  CredentialSchemaReference as CredentialSchemaReferenceJwt,
  CredentialStatus as CredentialStatusJwt,
  CredentialSubject as CredentialSubjectJwt,
  IssueCredentialPayload as IssueCredentialPayloadJwt,
  IssueCredentialResult as IssueCredentialResultJwt,
  ProofVerification as ProofVerificationJwt,
  SchemaProperty as SchemaPropertyJwt,
  SignerOptions as SignerOptionsJwt,
  TypeOptions as TypeOptionsJwt,
  UnsignedCredential as UnsignedCredentialJwt,
  VerifyProofPayload as VerifyProofPayloadJwt,
} from './vade-jwt-vc';

export interface IssueCredentialResultBbs {
  credential: UnfinishedCredentialBbs;
}

export interface RequestCredentialResultBbs {
  credentialRequest: CredentialRequestBbs;
  signatureBlinding?: string;
}

export type CreateRevocationRegistryResult = RevocationListCredential;
export type VerifiableCredential = CredentialBbs | CredentialJwt;
export type CredentialOffer = CredentialOfferBbs;
export type CredentialProposal = CredentialProposalBbs;
export type CredentialSchema = CredentialSchemaBbs;
export type EncodedCredentialValueBbs = string;
export type EncodedCredentialValue = EncodedCredentialValueBbs;
export type IssueCredentialResult = IssueCredentialResultBbs | IssueCredentialResultJwt;
export type MasterSecret = MasterSecretBbs;
export type MasterSecretBbs = string;
export type ProofCredential = ProofCredentialBbs;
export type ProofPresentation = ProofPresentationBbs;
export type ProofRequest = ProofRequestBbs;
export type RequestCredentialResult = RequestCredentialResultBbs;
export type SchemaProperty = SchemaPropertyBbs | SchemaPropertyJwt;
export type SubProofRequest = SubProofRequestBbs;
export type UnsignedCredential = UnsignedCredentialBbs | UnsignedCredentialJwt;

export {
  AssertionProofJwt,
  CredentialBbs,
  CredentialJwt,
  CredentialOfferBbs,
  CredentialProposalBbs,
  CredentialRequestBbs,
  CredentialSchemaBbs,
  CredentialSchemaReferenceJwt,
  CredentialStatusJwt,
  CredentialSubjectJwt,
  IssueCredentialPayloadJwt,
  IssueCredentialResultJwt,
  ProofPresentationBbs,
  ProofRequestBbs,
  ProofVerificationJwt,
  RevocationListCredential,
  SchemaPropertyBbs,
  SignerOptionsJwt,
  SubProofRequestBbs,
  TypeOptionsJwt,
  UnfinishedCredentialBbs,
  UnsignedCredentialBbs,
  UnsignedCredentialJwt,
  VerifyProofPayloadJwt,
};
