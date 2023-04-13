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

#[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
use std::os::raw::c_void;
use vade::Vade;

#[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
use crate::helpers::Credential;
#[cfg(feature = "plugin-did-sidetree")]
use crate::helpers::Did;
#[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
use crate::in3_request_list::ResolveHttpRequest;
use crate::{
    api::{vade_bundle::get_vade, vade_evan_error::VadeEvanError},
    helpers::VersionInfo,
};

pub const DEFAULT_TARGET: &str = "substrate-dev.trust-trace.com";
pub const DEFAULT_SIGNER: &str = "local";

fn get_first_result(results: Vec<Option<String>>) -> Result<String, VadeEvanError> {
    if results.is_empty() {
        return Err(VadeEvanError::NoResults);
    }
    let empty_result = String::new();
    let result = results[0].as_ref().unwrap_or(&empty_result);

    Ok(result.to_string())
}

pub struct VadeEvanConfig<'a> {
    pub target: &'a str,
    pub signer: &'a str,
    #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
    pub request_id: *const c_void,
    #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
    pub request_function_callback: ResolveHttpRequest,
}

/// A [`VadeEvan`] instance is your single point of contact for interacting with DIDs and VCs.
pub struct VadeEvan {
    vade: Vade,
}

impl VadeEvan {
    /// Creates new VadeEvan instance, vectors are initialized as empty.
    pub fn new(config: VadeEvanConfig) -> Result<Self, VadeEvanError> {
        match get_vade(
            &config.target,
            &config.signer,
            #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
            config.request_id,
            #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
            config.request_function_callback,
        ) {
            Ok(vade) => Ok(Self { vade }),
            Err(vade_error) => Err(VadeEvanError::InitializationFailed {
                source_message: vade_error.to_string(),
            }),
        }
    }

    /// Creates a new DID. May also persist a DID document for it, depending on plugin implementation.
    ///
    /// # Arguments
    ///
    /// * `did_method` - did method to cater to, usually also used by plugins to decide if a plugins will process the request
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.did_create("did:example", "", "").await?;
    ///             println!("created new did: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn did_create(
        &mut self,
        did_method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(self.vade.did_create(did_method, options, payload).await?)
    }

    /// Fetch data about a DID. This usually returns a DID document.
    ///
    /// # Arguments
    ///
    /// * `did` - did to fetch data for
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.did_resolve("did:example:123").await?;
    ///             println!("got did: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn did_resolve(&mut self, did: &str) -> Result<String, VadeEvanError> {
        get_first_result(self.vade.did_resolve(did).await?)
    }

    /// Updates data related to a DID. May also persist a DID document for it, depending on plugin implementation.
    ///
    /// # Arguments
    ///
    /// * `did` - DID to update data for
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.did_update("did:example", "", "").await?;
    ///             println!("did successfully updated: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn did_update(
        &mut self,
        did: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(self.vade.did_update(did, options, payload).await?)
    }

    /// Processes a DIDComm message as received, this may prepare a matching response for it
    /// if the DIDComm message can be interpreted and answered by a plugin's implementation.
    ///
    /// This response **may** be sent, depending on the configuration and implementation of
    /// underlying plugins, but it is usually also returned as response to this request.
    ///
    /// # Arguments
    ///
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (usually a raw DIDComm message)
    ///
    /// # Example
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.didcomm_receive("", "").await?;
    ///             println!("received DIDComm message: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn didcomm_receive(
        &mut self,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(self.vade.didcomm_receive(options, payload).await?)
    }

    /// Processes a DIDComm message and prepares it for sending.
    ///
    /// It **may** be sent, depending on the configuration and implementation of underlying plugins.
    ///
    /// # Arguments
    ///
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (usually a raw DIDComm message)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.didcomm_send("", "").await?;
    ///             println!("prepared DIDComm message: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn didcomm_send(
        &mut self,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(self.vade.didcomm_send(options, payload).await?)
    }

    /// Gets information about version of `vade_evan` and dependencies prefixed with `evan-`.
    ///
    /// This can be useful to determine which versions of plugins are used to resolve vade calls.
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.get_version_info();
    ///             println!("vade_evan version info: \n{}", &result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub fn get_version_info(&self) -> String {
        VersionInfo::get_version_info()
    }

    /// Creates a new zero-knowledge proof credential offer. This message is the response
    /// to a credential proposal. `create_credential_offer` function can be used in the same step
    /// and produces the same output as `vc_zkp_create_credential_offer` but uses a simpler argument setup.
    ///
    /// # Arguments
    ///
    /// * `schema_did` - schema to create the offer for
    /// * `use_valid_until` - true if `validUntil` will be present in credential
    /// * `issuer_did` - DID of issuer
    /// * `subject_did` - DID of subject (or `None` no subject id is used)
    ///
    /// # Returns
    /// * credential offer as JSON serialized [`BbsCredentialOffer`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.BbsCredentialOffer.html)
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         const ISSUER_DID: &str = "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6";
    ///         const SCHEMA_DID: &str = "did:evan:EiACv4q04NPkNRXQzQHOEMa3r1p_uINgX75VYP2gaK5ADw";
    ///         const SUBJECT_DID: &str = "did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f";
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let offer_str = vade_evan
    ///                 .helper_create_credential_offer(
    ///                     SCHEMA_DID,
    ///                     false,
    ///                     ISSUER_DID,
    ///                     Some(SUBJECT_DID),
    ///                 )
    ///                 .await?;
    ///
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    #[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
    pub async fn helper_create_credential_offer(
        &mut self,
        schema_did: &str,
        use_valid_until: bool,
        issuer_did: &str,
        subject_did: Option<&str>,
    ) -> Result<String, VadeEvanError> {
        let mut credential = Credential::new(self)?;
        credential
            .create_credential_offer(schema_did, use_valid_until, issuer_did, subject_did)
            .await
            .map_err(|err| err.into())
    }

    /// Creates a credential request. This function is used to create a credential request which is sent to Issuer
    ///
    /// # Arguments
    ///
    /// * `issuer_public_key` - issuer public key
    /// * `bbs_secret` - master secret of the holder/receiver
    /// * `credential_values` - JSON string with cleartext values to be signed in the credential
    /// * `credential_offer` - JSON string with credential offer by issuer
    /// * `credential_schema_did` - did for credential schema
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let credential_offer = r#"{
    ///                "issuer": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906",
    ///                "subject": "did:any:abc",
    ///                "nonce": "QqJR4o6joiApYVXX7JLbRIZBQ9QprlFpewo8GbojIKY=",
    ///                "credentialMessageCount": 2
    ///            }"#;
    ///            let bbs_secret = r#"OASkVMA8q6b3qJuabvgaN9K1mKoqptCv4SCNvRmnWuI="#;
    ///            let credential_values = r#"{
    ///                "email": "value@x.com"
    ///            }"#;
    ///            let issuer_pub_key = r#"jCv7l26izalfcsFe6j/IqtVlDolo2Y3lNld7xOG63GjSNHBVWrvZQe2O859q9JeVEV4yXtfYofGQSWrMVfgH5ySbuHpQj4fSgLu4xXyFgMidUO1sIe0NHRcXpOorP01o"#;
    ///
    ///            let credential_request = vade_evan
    ///                .helper_create_credential_request(
    ///                    issuer_pub_key,
    ///                    bbs_secret,
    ///                    credential_values,
    ///                    credential_offer,
    ///                    "did:evan:EiACv4q04NPkNRXQzQHOEMa3r1p_uINgX75VYP2gaK5ADw",
    ///                )
    ///                .await?;
    ///             println!("created credential request: {}", credential_request);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    #[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
    pub async fn helper_create_credential_request(
        &mut self,
        issuer_public_key: &str,
        bbs_secret: &str,
        credential_values: &str,
        credential_offer: &str,
        credential_schema_did: &str,
    ) -> Result<String, VadeEvanError> {
        let mut credential = Credential::new(self)?;
        credential
            .create_credential_request(
                issuer_public_key,
                bbs_secret,
                credential_values,
                credential_offer,
                credential_schema_did,
            )
            .await
            .map_err(|err| err.into())
    }

    /// Verifies a given credential by checking if given master secret was incorporated
    /// into proof and if proof was signed with issuers public key.
    ///
    /// # Arguments
    ///
    /// * `credential` - credential to verify as serialized JSON
    /// * `master_secret` - master secret incorporated as a blinded value into the proof of the credential
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let credential = r###"{
    ///                 "id": "uuid:70b7ec4e-f035-493e-93d3-2cf5be4c7f88",
    ///                 "type": [
    ///                     "VerifiableCredential"
    ///                 ],
    ///                 "proof": {
    ///                     "type": "BbsBlsSignature2020",
    ///                     "created": "2023-02-01T14:08:17.000Z",
    ///                     "signature": "kvSyi40dnZ5S3/mSxbSUQGKLpyMXDQNLCPtwDGM9GsnNNKF7MtaFHXIbvXaVXku0EY/n2uNMQ2bmK2P0KEmzgbjRHtzUOWVdfAnXnVRy8/UHHIyJR471X6benfZk8KG0qVqy+w67z9g628xRkFGA5Q==",
    ///                     "proofPurpose": "assertionMethod",
    ///                     "verificationMethod": "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA#bbs-key-1",
    ///                     "credentialMessageCount": 13,
    ///                     "requiredRevealStatements": []
    ///                 },
    ///                 "issuer": "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA",
    ///                 "@context": [
    ///                     "https://www.w3.org/2018/credentials/v1",
    ///                     "https://schema.org/",
    ///                     "https://w3id.org/vc-revocation-list-2020/v1"
    ///                 ],
    ///                 "issuanceDate": "2023-02-01T14:08:09.849Z",
    ///                 "credentialSchema": {
    ///                     "id": "did:evan:EiCimsy3uWJ7PivWK0QUYSCkImQnjrx6fGr6nK8XIg26Kg",
    ///                     "type": "EvanVCSchema"
    ///                 },
    ///                 "credentialStatus": {
    ///                     "id": "did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA#4",
    ///                     "type": "RevocationList2020Status",
    ///                     "revocationListIndex": "4",
    ///                     "revocationListCredential": "did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA"
    ///                 },
    ///                 "credentialSubject": {
    ///                     "id": "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA",
    ///                     "data": {
    ///                         "bio": "biography"
    ///                     }
    ///                 }
    ///             }"###;
    ///             let master_secret = "QyRmu33oIQFNW+dSI5wex3u858Ra7yx5O1tsxJgQvu8=";
    ///
    ///             // verify the credential issuer
    ///             vade_evan
    ///                 .helper_verify_credential(credential, master_secret)
    ///                 .await?;
    ///
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    #[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
    pub async fn helper_verify_credential(
        &mut self,
        credential: &str,
        master_secret: &str,
    ) -> Result<(), VadeEvanError> {
        let mut credential_helper = Credential::new(self)?;
        credential_helper
            .verify_credential(credential, master_secret)
            .await
            .map_err(|err| err.into())
    }

    /// Requests a proof for a credential.
    /// The proof request consists of the fields the verifier wants to be revealed per schema.
    ///
    /// # Arguments
    ///
    /// * `schema_did` - DID of schema to request proof for
    /// * `revealed_attributes` - list of names of revealed attributes in specified schema, reveals all if omitted
    ///
    /// # Returns
    /// * `Option<String>` - A `ProofRequest` as JSON
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let schema_did = "did:evan:EiBrPL8Yif5NWHOzbKvyh1PX1wKVlWvIa6nTG1v8PXytvg";
    ///             let revealed_attributes = Some(r#"["zip", "country"]"#);
    ///
    ///             vade_evan
    ///                 .helper_create_proof_request(schema_did, revealed_attributes)
    ///                 .await?;
    ///
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    #[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
    pub async fn helper_create_proof_request(
        &mut self,
        schema_did: &str,
        revealed_attributes: Option<&str>,
    ) -> Result<String, VadeEvanError> {
        use crate::helpers::Presentation;

        let mut presentation_helper = Presentation::new(self)?;
        presentation_helper
            .create_proof_request(schema_did, revealed_attributes)
            .await
            .map_err(|err| err.into())
    }

    /// Creates a presentation.
    /// The presentation has proof and requested credentials.
    ///
    /// # Arguments
    ///
    /// * `proof_request` - proof request for presentation
    /// * `credential` - credential to be shared in presentation
    /// * `master_secret` - user's master secret
    /// * `signing_key` - users secp256k1 private signing key
    /// * `revealed_attributes` - list of names of revealed attributes in specified schema,
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         const SIGNER_PRIVATE_KEY: &str =
    ///         "dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106";
    ///         const MASTER_SECRET: &str = "QyRmu33oIQFNW+dSI5wex3u858Ra7yx5O1tsxJgQvu8=";
    ///         
    ///         const SCHEMA_DID: &str = "did:evan:EiBrPL8Yif5NWHOzbKvyh1PX1wKVlWvIa6nTG1v8PXytvg"; // evan.address
    ///         const CREDENTIAL: &str = r###"{
    ///             "id": "uuid:70b7ec4e-f035-493e-93d3-2cf5be4c7f88",
    ///             "type": [
    ///                 "VerifiableCredential"
    ///             ],
    ///             "proof": {
    ///                 "type": "BbsBlsSignature2020",
    ///                 "created": "2023-02-01T14:08:17.000Z",
    ///                 "signature": "kvSyi40dnZ5S3/mSxbSUQGKLpyMXDQNLCPtwDGM9GsnNNKF7MtaFHXIbvXaVXku0EY/n2uNMQ2bmK2P0KEmzgbjRHtzUOWVdfAnXnVRy8/UHHIyJR471X6benfZk8KG0qVqy+w67z9g628xRkFGA5Q==",
    ///                 "proofPurpose": "assertionMethod",
    ///                 "verificationMethod": "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA#bbs-key-1",
    ///                 "credentialMessageCount": 13,
    ///                 "requiredRevealStatements": []
    ///             },
    ///             "issuer": "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA",
    ///             "@context": [
    ///                 "https://www.w3.org/2018/credentials/v1",
    ///                 "https://schema.org/",
    ///                 "https://w3id.org/vc-revocation-list-2020/v1"
    ///             ],
    ///             "issuanceDate": "2023-02-01T14:08:09.849Z",
    ///             "credentialSchema": {
    ///                 "id": "did:evan:EiCimsy3uWJ7PivWK0QUYSCkImQnjrx6fGr6nK8XIg26Kg",
    ///                 "type": "EvanVCSchema"
    ///             },
    ///             "credentialStatus": {
    ///                 "id": "did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA#4",
    ///                 "type": "RevocationList2020Status",
    ///                 "revocationListIndex": "4",
    ///                 "revocationListCredential": "did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA"
    ///             },
    ///             "credentialSubject": {
    ///                 "id": "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA",
    ///                 "data": {
    ///                     "bio": "biography"
    ///                 }
    ///             }
    ///         }"###;
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let revealed_attributes = Some(r#"["zip", "country"]"#);
    ///             let proof_request_str = vade_evan
    ///                 .helper_create_proof_request(SCHEMA_DID, revealed_attributes)
    ///                 .await?;
    ///
    ///             let presentation_result = vade_evan
    ///               .helper_create_presentation(
    ///                   &proof_request_str,
    ///                   CREDENTIAL,
    ///                   MASTER_SECRET,
    ///                   SIGNER_PRIVATE_KEY,
    ///                   None,
    ///                )
    ///                .await;
    ///
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    #[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
    pub async fn helper_create_presentation(
        &mut self,
        proof_request_str: &str,
        credential_str: &str,
        master_secret: &str,
        signing_key: &str,
        revealed_attributes: Option<&str>,
    ) -> Result<String, VadeEvanError> {
        use crate::helpers::Presentation;

        let mut presentation_helper = Presentation::new(self)?;
        presentation_helper
            .create_presentation(
                proof_request_str,
                credential_str,
                master_secret,
                signing_key,
                revealed_attributes,
            )
            .await
            .map_err(|err| err.into())
    }
    /// Revokes a given credential with the help of vade and updates revocation list credential
    ///
    /// # Arguments
    ///
    /// * `credential` - credential to be revoked as serialized JSON
    /// * `update_key_jwk` - update key in jwk format as serialized JSON
    /// * `private_key` - private key for local signer to be used for signing
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let credential = r###"{
    ///                 "id": "uuid:70b7ec4e-f035-493e-93d3-2cf5be4c7f88",
    ///                 "type": [
    ///                     "VerifiableCredential"
    ///                 ],
    ///                 "proof": {
    ///                     "type": "BbsBlsSignature2020",
    ///                     "created": "2023-02-01T14:08:17.000Z",
    ///                     "signature": "kvSyi40dnZ5S3/mSxbSUQGKLpyMXDQNLCPtwDGM9GsnNNKF7MtaFHXIbvXaVXku0EY/n2uNMQ2bmK2P0KEmzgbjRHtzUOWVdfAnXnVRy8/UHHIyJR471X6benfZk8KG0qVqy+w67z9g628xRkFGA5Q==",
    ///                     "proofPurpose": "assertionMethod",
    ///                     "verificationMethod": "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA#bbs-key-1",
    ///                     "credentialMessageCount": 13,
    ///                     "requiredRevealStatements": []
    ///                 },
    ///                 "issuer": "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA",
    ///                 "@context": [
    ///                     "https://www.w3.org/2018/credentials/v1",
    ///                     "https://schema.org/",
    ///                     "https://w3id.org/vc-revocation-list-2020/v1"
    ///                 ],
    ///                 "issuanceDate": "2023-02-01T14:08:09.849Z",
    ///                 "credentialSchema": {
    ///                     "id": "did:evan:EiCimsy3uWJ7PivWK0QUYSCkImQnjrx6fGr6nK8XIg26Kg",
    ///                     "type": "EvanVCSchema"
    ///                 },
    ///                 "credentialStatus": {
    ///                     "id": "did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA#4",
    ///                     "type": "RevocationList2020Status",
    ///                     "revocationListIndex": "4",
    ///                     "revocationListCredential": "did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA"
    ///                 },
    ///                 "credentialSubject": {
    ///                     "id": "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA",
    ///                     "data": {
    ///                         "bio": "biography"
    ///                     }
    ///                 }
    ///             }"###;
    ///             let update_key_jwk = r###"{
    ///                 "kty": "EC",
    ///                 "crv": "secp256k1",
    ///                 "x": "n194_Pew6DvVr1vFsInIP5XlJESYIj_h3-_5XJ5Fudw",
    ///                 "y": "Z-o5enGPMVFi4U4oA2prWLYDcyATXtHvkEO2yvsOBbI",
    ///                 "d": "AtmtD2JOaydG5WAHrjkYS_VzFkWo2B0Ok-8T3uClFt4"
    ///             }"###;
    ///
    ///             // revoke the credential issuer
    ///             vade_evan
    ///                 .helper_revoke_credential(credential, update_key_jwk, "dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106")
    ///                 .await?;
    ///
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    #[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
    pub async fn helper_revoke_credential(
        &mut self,
        credential: &str,
        update_key_jwk: &str,
        private_key: &str,
    ) -> Result<String, VadeEvanError> {
        let mut credential_helper = Credential::new(self)?;
        credential_helper
            .revoke_credential(credential, update_key_jwk, private_key)
            .await
            .map_err(|err| err.into())
    }

    /// Creates a new zero-knowledge proof self issued credential.
    /// `create_self_issued_credential` function combines `vc_zkp_create_credential_offer`,
    /// `vc_zkp_create_credential_request`, `vc_zkp_issue_credential` and `vc_zkp_finish_credential`
    /// and produces self-issued credential with blind signature.
    ///
    /// # Arguments
    ///
    /// * `schema_did` - schema to create the credential
    /// * `credential_subject_str` - JSON string of CredentialSubject structure
    /// * `bbs_secret` - BBS secret
    /// * `bbs_private_key` - BBS private key
    /// * `credential_revocation_did` - revocation list DID
    /// * `credential_revocation_id` - index in revocation list
    /// * `exp_date` - expiration date, string, e.g. "1722-12-03T14:23:42.120Z" (or `None` if no expiration date is used)
    ///
    /// # Returns
    /// * credential as JSON serialized [`BbsCredential`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.BbsCredential.html)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         const SCHEMA_DID: &str = "did:evan:EiACv4q04NPkNRXQzQHOEMa3r1p_uINgX75VYP2gaK5ADw";
    ///         const CREDENTIAL_SUBJECT_STR: &str = r#"{
    ///                                                  "id":"did:evan:EiAOD3RUcQrRXNZIR8BIEXuGvixcUj667_5fdeX-Sp3PpA",
    ///                                                  "data":{
    ///                                                           "email":"value@x.com"
    ///                                                         }
    ///                                                }"#;
    ///         const BBS_SECRET: &str = "GRsdzRB0pf/8MKP/ZBOM2BEV1A8DIDfmLh8T3b1hPKc=";
    ///         const BBS_PRIVATE_KEY: &str = "WWTZW8pkz35UnvsUCEsof2CJmNHaJQ/X+B5xjWcHr/I=";
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let offer_str = vade_evan
    ///                 .helper_create_self_issued_credential(
    ///                     SCHEMA_DID,
    ///                     CREDENTIAL_SUBJECT_STR,
    ///                     BBS_SECRET,
    ///                     BBS_PRIVATE_KEY,
    ///                     "did:revoc:12345",
    ///                     "1",
    ///                     None,
    ///                 )
    ///                 .await?;
    ///
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    #[cfg(all(feature = "plugin-vc-zkp-bbs", feature = "plugin-did-sidetree"))]
    pub async fn helper_create_self_issued_credential(
        &mut self,
        schema_did: &str,
        credential_subject_str: &str,
        bbs_secret: &str,
        bbs_private_key: &str,
        credential_revocation_did: Option<&str>,
        credential_revocation_id: Option<&str>,
        exp_date: Option<&str>,
    ) -> Result<String, VadeEvanError> {
        let mut credential = Credential::new(self)?;
        credential
            .create_self_issued_credential(
                schema_did,
                credential_subject_str,
                bbs_secret,
                bbs_private_key,
                credential_revocation_did,
                credential_revocation_id,
                exp_date,
            )
            .await
            .map_err(|err| err.into())
    }

    /// Runs a custom function, this allows to use `Vade`s API for custom calls, that do not belong
    /// to `Vade`s core functionality but may be required for a projects use cases.
    ///
    /// # Arguments
    ///
    /// * `method` - method to call a function for (e.g. "did:example")
    /// * `function` - function to call (e.g. "test connection")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.run_custom_function("did:example", "test connection", "", "").await?;
    ///             println!("connection status is: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn run_custom_function(
        &mut self,
        method: &str,
        function: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .run_custom_function(method, function, options, payload)
                .await?,
        )
    }

    /// Creates a new zero-knowledge proof credential definition. A credential definition holds cryptographic key material
    /// and is needed by an issuer to issue a credential, thus needs to be created before issuance. A credential definition
    /// is always bound to one credential schema.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential definition for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.vc_zkp_create_credential_definition("did:example", "", "").await?;
    ///             println!("created a credential definition: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn vc_zkp_create_credential_definition(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .vc_zkp_create_credential_definition(method, options, payload)
                .await?,
        )
    }

    /// Creates a new zero-knowledge proof credential offer. This message is the response to a credential proposal.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential offer for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.vc_zkp_create_credential_offer("did:example", "", "").await?;
    ///             println!("created a credential offer: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn vc_zkp_create_credential_offer(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .vc_zkp_create_credential_offer(method, options, payload)
                .await?,
        )
    }

    /// Creates a new zero-knowledge proof credential proposal. This message is the first in the
    /// credential issuance flow.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential proposal for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.vc_zkp_create_credential_proposal("did:example", "", "").await?;
    ///             println!("created a credential proposal: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn vc_zkp_create_credential_proposal(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .vc_zkp_create_credential_proposal(method, options, payload)
                .await?,
        )
    }

    /// Creates a new zero-knowledge proof credential schema. The schema specifies properties a credential
    /// includes, both optional and mandatory.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential schema for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.vc_zkp_create_credential_schema("did:example", "", "").await?;
    ///             println!("created a credential schema: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn vc_zkp_create_credential_schema(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .vc_zkp_create_credential_schema(method, options, payload)
                .await?,
        )
    }

    /// Creates a new revocation registry definition. The definition consists of a public and a private part.
    /// The public part holds the cryptographic material needed to create non-revocation proofs. The private part
    /// needs to reside with the registry owner and is used to revoke credentials.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a revocation registry definition for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.vc_zkp_create_revocation_registry_definition("did:example", "", "").await?;
    ///             println!("created a revocation registry definition: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn vc_zkp_create_revocation_registry_definition(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .vc_zkp_create_revocation_registry_definition(method, options, payload)
                .await?,
        )
    }

    /// Updates a revocation registry for a zero-knowledge proof. This step is necessary after revocation one or
    /// more credentials.
    ///
    /// # Arguments
    ///
    /// * `method` - method to update a revocation registry for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.vc_zkp_update_revocation_registry("did:example", "", "").await?;
    ///             println!("updated revocation registry: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn vc_zkp_update_revocation_registry(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .vc_zkp_update_revocation_registry(method, options, payload)
                .await?,
        )
    }

    /// Issues a new credential. This requires an issued schema, credential definition, an active revocation
    /// registry and a credential request message.
    ///
    /// # Arguments
    ///
    /// * `method` - method to issue a credential for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.vc_zkp_issue_credential("did:example", "", "").await?;
    ///             println!("issued credential: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn vc_zkp_issue_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .vc_zkp_issue_credential(method, options, payload)
                .await?,
        )
    }

    /// Finishes a credential, e.g. by incorporating the prover's master secret into the credential signature after issuance.
    ///
    /// # Arguments
    ///
    /// * `method` - method to update a finish credential for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.vc_zkp_finish_credential("did:example", "", "").await?;
    ///             println!("issued credential: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn vc_zkp_finish_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .vc_zkp_finish_credential(method, options, payload)
                .await?,
        )
    }

    /// Presents a proof for a zero-knowledge proof credential. A proof presentation is the response to a
    /// proof request.
    ///
    /// # Arguments
    ///
    /// * `method` - method to presents a proof for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.vc_zkp_present_proof("did:example", "", "").await?;
    ///             println!("created a proof presentation: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn vc_zkp_present_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .vc_zkp_present_proof(method, options, payload)
                .await?,
        )
    }

    /// Requests a credential. This message is the response to a credential offering.
    ///
    /// # Arguments
    ///
    /// * `method` - method to request a credential for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.vc_zkp_request_credential("did:example", "", "").await?;
    ///             println!("created credential request: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn vc_zkp_request_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .vc_zkp_request_credential(method, options, payload)
                .await?,
        )
    }

    /// Requests a zero-knowledge proof for one or more credentials issued under one or more specific schemas.
    ///
    /// # Arguments
    ///
    /// * `method` - method to request a proof for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.vc_zkp_request_proof("did:example", "", "").await?;
    ///             println!("created proof request: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn vc_zkp_request_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .vc_zkp_request_proof(method, options, payload)
                .await?,
        )
    }

    /// Revokes a credential. After revocation the published revocation registry needs to be updated with information
    /// returned by this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to revoke a credential for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.vc_zkp_revoke_credential("did:example", "", "").await?;
    ///             println!("revoked credential: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn vc_zkp_revoke_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .vc_zkp_revoke_credential(method, options, payload)
                .await?,
        )
    }

    /// Verifies one or multiple proofs sent in a proof presentation.
    ///
    /// # Arguments
    ///
    /// * `method` - method to verify a proof for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    ///     if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///         use anyhow::Result;
    ///         use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///         async fn example() -> Result<()> {
    ///             let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///             let result = vade_evan.vc_zkp_verify_proof("did:example", "", "").await?;
    ///             println!("verified proof: {}", result);
    ///             Ok(())
    ///         }
    ///     } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    pub async fn vc_zkp_verify_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        get_first_result(
            self.vade
                .vc_zkp_verify_proof(method, options, payload)
                .await?,
        )
    }

    /// Creates a did with optional predefined keys and service endpoints
    ///
    /// # Arguments
    ///
    /// * `bbs_public_key` - base64 encoded bbs public key (Bls12381G2Key2020)
    /// * `signing_key` - base64 encoded public key (JsonWebKey2020)
    /// * `service_endpoint` - service endpoint url
    /// * `update_key` - JSON string containing update key for did in JWK format,
    /// * `recovery_key` - JSON string containing recovery key for did in JWK format,
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    /// if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///     use anyhow::Result;
    ///     use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///     async fn example() -> Result<()> {
    ///         let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///         let bbs_public_key =  "LwDjc3acetrEsbccFI4zSy1+AFqUbkEUf6Sm0OxIdhU=";
    ///         let signing_key = None;
    ///         let service_url = "www.example.service";
    ///
    ///         let create_response = vade_evan
    ///            .helper_did_create(
    ///                Some(bbs_public_key),
    ///                signing_key,
    ///                Some(service_url),
    ///                None,
    ///                None,
    ///            )
    ///            .await?;
    ///         println!("did create response: {}", create_response);
    ///         Ok(())
    ///        }
    ///    } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    #[cfg(feature = "plugin-did-sidetree")]
    pub async fn helper_did_create(
        &mut self,
        bbs_public_key: Option<&str>,
        signing_key: Option<&str>,
        service_endpoint: Option<&str>,
        update_key: Option<&str>,
        recovery_key: Option<&str>,
    ) -> Result<String, VadeEvanError> {
        let did = Did::new(self)?;
        did.create(
            bbs_public_key,
            signing_key,
            service_endpoint,
            update_key,
            recovery_key,
        )
        .await
    }

    /// Updates a did (add/remove public key jwk and add/remove service endpoint)
    ///
    /// # Arguments
    ///
    /// did: did to update,
    /// operation: type of did update to be performed ,
    /// update_key: JSON string containing pubilc key in JWK format,
    /// payload: payload of update command as per operation,
    ///
    /// # Example
    ///
    /// ```
    /// cfg_if::cfg_if! {
    /// if #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))] {
    ///
    ///     use anyhow::Result;
    ///     use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    ///     async fn example() -> Result<()> {
    ///         let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///         let did = "did:evan:0x123334233232";
    ///         let update_key = r#"{"kty":"EC","crv":"secp256k1","x":"W8rj8Dko_f0KgqY-nzCvzy_pNbVmYyiaY1GpiuvZKsw","y":"E2cKPqGtq55iiyZIdTCe59HgeQ1bdnMcNdbf9tI5ogo","d":"yZv5g_rjyC0nnUii7pxEh7V2M6XZHeJCu5OjfLMNlSI"}"#;
    ///         let operation = r#"AddServiceEndpoint"#;
    ///         let service = r#"{"id":"sds","r#type":"SecureDataStrore","service_endpoint":"www.google.com"}"#;
    ///         let payload = &serde_json::to_string(&service)?;
    ///         let update_response = vade_evan
    ///            .helper_did_update(did, operation, update_key, payload)
    ///            .await?;
    ///         println!("did update response: {}", update_response);
    ///         Ok(())
    ///        }
    ///    } else {
    ///         // currently no example for capability-sdk and target-c-lib/target-java-lib
    ///     }
    /// }
    /// ```
    #[cfg(feature = "plugin-did-sidetree")]
    pub async fn helper_did_update(
        &mut self,
        did: &str,
        operation: &str,
        update_key: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        let did_helper = Did::new(self)?;

        did_helper.update(did, operation, update_key, payload).await
    }
}

#[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
#[cfg(test)]
mod tests {
    use crate::{VadeEvan, VadeEvanConfig};

    #[test]
    fn can_be_created() {
        let vade_evan = VadeEvan::new(VadeEvanConfig {
            target: "test",
            signer: "remote|http://127.0.0.1:7070/key/sign",
        });

        assert!(vade_evan.is_ok());
    }
}
