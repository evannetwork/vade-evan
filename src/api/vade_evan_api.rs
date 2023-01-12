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

#[cfg(feature = "sdk")]
use std::os::raw::c_void;
use vade::Vade;

use super::{vade_bundle::get_vade, vade_evan_error::VadeEvanError, VersionInfo};
#[cfg(feature = "sdk")]
use crate::in3_request_list::ResolveHttpRequest;

pub const DEFAULT_TARGET: &str = "substrate-dev.trust-trace.com";
pub const DEFAULT_SIGNER: &str = "local";

pub struct VadeEvanConfig<'a> {
    pub target: &'a str,
    pub signer: &'a str,
    #[cfg(feature = "sdk")]
    pub request_id: *const c_void,
    #[cfg(feature = "sdk")]
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
            #[cfg(feature = "sdk")]
            config.request_id,
            #[cfg(feature = "sdk")]
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.did_create("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("created new did: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn did_create(
        &mut self,
        did_method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self.vade.did_create(did_method, options, payload).await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.did_resolve("did:example:123").await?;
    ///     if !results.is_empty() {
    ///         println!("got did: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn did_resolve(&mut self, did: &str) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self.vade.did_resolve(did).await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.did_update("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("did successfully updated: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn did_update(
        &mut self,
        did: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self.vade.did_update(did, options, payload).await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.didcomm_receive("", "").await?;
    ///     if !results.is_empty() {
    ///         println!("received DIDComm message: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn didcomm_receive(
        &mut self,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self.vade.didcomm_receive(options, payload).await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.didcomm_send("", "").await?;
    ///     if !results.is_empty() {
    ///         println!("prepared DIDComm message: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn didcomm_send(
        &mut self,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self.vade.didcomm_send(options, payload).await?)
    }

    /// Gets information about version of `vade_evan` and dependencies prefixed with `evan-`.
    ///
    /// This can be useful to determine which versions of plugins are used to resolve vade calls.
    ///
    /// # Example
    ///
    /// ``
    /// use anyhow::Result;
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let result = vade_evan.get_version_info();
    ///     println!("vade_evan version info: \n{}", &result);
    ///     Ok(())
    /// }
    /// ``
    pub fn get_version_info(&self) -> String {
        VersionInfo::get_version_info()
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.run_custom_function("did:example", "test connection", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("connection status is: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn run_custom_function(
        &mut self,
        method: &str,
        function: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .run_custom_function(method, function, options, payload)
            .await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.vc_zkp_create_credential_definition("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("created a credential definition: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn vc_zkp_create_credential_definition(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .vc_zkp_create_credential_definition(method, options, payload)
            .await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.vc_zkp_create_credential_offer("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("created a credential offer: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn vc_zkp_create_credential_offer(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .vc_zkp_create_credential_offer(method, options, payload)
            .await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.vc_zkp_create_credential_proposal("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("created a credential proposal: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn vc_zkp_create_credential_proposal(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .vc_zkp_create_credential_proposal(method, options, payload)
            .await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.vc_zkp_create_credential_schema("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("created a credential schema: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn vc_zkp_create_credential_schema(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .vc_zkp_create_credential_schema(method, options, payload)
            .await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.vc_zkp_create_revocation_registry_definition("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("created a revocation registry definition: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn vc_zkp_create_revocation_registry_definition(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .vc_zkp_create_revocation_registry_definition(method, options, payload)
            .await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.vc_zkp_update_revocation_registry("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("updated revocation registry: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn vc_zkp_update_revocation_registry(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .vc_zkp_update_revocation_registry(method, options, payload)
            .await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.vc_zkp_issue_credential("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("issued credential: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn vc_zkp_issue_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .vc_zkp_issue_credential(method, options, payload)
            .await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.vc_zkp_finish_credential("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("issued credential: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn vc_zkp_finish_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .vc_zkp_finish_credential(method, options, payload)
            .await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.vc_zkp_present_proof("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("created a proof presentation: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn vc_zkp_present_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .vc_zkp_present_proof(method, options, payload)
            .await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.vc_zkp_request_credential("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("created credential request: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn vc_zkp_request_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .vc_zkp_request_credential(method, options, payload)
            .await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.vc_zkp_request_proof("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("created proof request: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn vc_zkp_request_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .vc_zkp_request_proof(method, options, payload)
            .await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.vc_zkp_revoke_credential("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("revoked credential: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn vc_zkp_revoke_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .vc_zkp_revoke_credential(method, options, payload)
            .await?)
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
    /// use anyhow::{anyhow, Result};
    /// use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_TARGET, DEFAULT_SIGNER};
    ///
    /// async fn example() -> Result<()> {
    ///     let mut vade_evan = VadeEvan::new(VadeEvanConfig { target: DEFAULT_TARGET, signer: DEFAULT_SIGNER })?;
    ///     let results = vade_evan.vc_zkp_verify_proof("did:example", "", "").await?;
    ///     if !results.is_empty() {
    ///         println!("verified proof: {}", results[0].as_ref().ok_or(anyhow!("result not found"))?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn vc_zkp_verify_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<Vec<Option<String>>, VadeEvanError> {
        Ok(self
            .vade
            .vc_zkp_verify_proof(method, options, payload)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::{VadeEvan, VadeEvanConfig};

    #[test]
    fn can_be_created() {
        let vade_evan = VadeEvan::new(VadeEvanConfig {
            target: "test",
            signer: "remote|http://127.0.0.1:7070/key/sign",
        });

        assert!(vade_evan.is_ok());
    }
}
