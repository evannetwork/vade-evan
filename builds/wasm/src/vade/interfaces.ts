export interface ServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string;
  [key: string]: string | string[];
}

export interface PublicKey {
  id: string;
  type: string[];
  publicKeyHex?: string
  publicKeyBase58?: string
  publicKeyBase64?: string
  ethereumAddress?: string
  publicKeyPem?: string
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyHex?: string
  publicKeyBase58?: string
  publicKeyBase64?: string
  ethereumAddress?: string
  publicKeyPem?: string
}

export interface DIDDocument {
  '@context': string|string[]|(string|Record<string, string|Record<string, string>>)[];
  id: string;
  alsoKnownAs?: string[];
  publicKey: PublicKey[]; // Deprecated, kept for backwards compatibility
  verificationMethod: VerificationMethod[];
  authentication?: (string|VerificationMethod)[];
  assertionMethod?: (string|VerificationMethod)[];
  keyAgreement?: (string|VerificationMethod)[];
  capabilityInvocation?: (string|VerificationMethod)[];
  capabilityDelegation?: (string|VerificationMethod)[];
  service?: ServiceEndpoint[];
  metaData?: Record<string, string>;
}
