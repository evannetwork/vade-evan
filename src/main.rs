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

extern crate clap;

use anyhow::{bail, Result};
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};

use vade_evan::{VadeEvan, VadeEvanConfig, DEFAULT_SIGNER, DEFAULT_TARGET};

// macro might be unused depending on feature combination
#[allow(unused_macros)]
macro_rules! wrap_vade2 {
    ($func_name:ident, $sub_m:ident) => {{
        let options = get_argument_value($sub_m, "options", None);
        let payload = get_argument_value($sub_m, "payload", None);
        get_vade_evan($sub_m)?
            .$func_name(&options, &payload)
            .await?
    }};
}

// macro might be unused depending on feature combination
#[allow(unused_macros)]
macro_rules! wrap_vade3 {
    ($func_name:ident, $sub_m:ident) => {{
        let method = get_argument_value($sub_m, "method", None);
        let options = get_argument_value($sub_m, "options", None);
        let payload = get_argument_value($sub_m, "payload", None);
        get_vade_evan($sub_m)?
            .$func_name(&method, &options, &payload)
            .await?
    }};
}

#[cfg(any(feature = "didcomm", feature = "vc-zkp-bbs"))]
const EVAN_METHOD: &str = "did:evan";

#[tokio::main]
async fn main() -> Result<()> {
    let matches = get_argument_matches()?;

    let result = match matches.subcommand() {
        #[cfg(any(feature = "did-read", feature = "did-write"))]
        ("did", Some(sub_m)) => match sub_m.subcommand() {
            #[cfg(feature = "did-write")]
            ("create", Some(sub_m)) => {
                let method = get_argument_value(&sub_m, "method", None);
                let options = get_argument_value(&sub_m, "options", None);
                let payload = get_argument_value(&sub_m, "payload", None);
                get_vade_evan(&sub_m)?
                    .did_create(&method, &options, &payload)
                    .await?
            }
            #[cfg(feature = "did-read")]
            ("resolve", Some(sub_m)) => {
                let did = get_argument_value(&sub_m, "did", None);
                get_vade_evan(&sub_m)?.did_resolve(&did).await?
            }
            #[cfg(feature = "did-write")]
            ("update", Some(sub_m)) => {
                let did = get_argument_value(&sub_m, "did", None);
                let options = get_argument_value(&sub_m, "options", None);
                let payload = get_argument_value(&sub_m, "payload", None);
                get_vade_evan(&sub_m)?
                    .did_update(&did, &options, &payload)
                    .await?
            }
            _ => {
                bail!("invalid subcommand");
            }
        },
        #[cfg(feature = "didcomm")]
        ("didcomm", Some(sub_m)) => match sub_m.subcommand() {
            ("send", Some(sub_m)) => {
                wrap_vade2!(didcomm_send, sub_m)
            }
            ("receive", Some(sub_m)) => {
                wrap_vade2!(didcomm_receive, sub_m)
            }
            ("create_keys", Some(sub_m)) => {
                get_vade_evan(&sub_m)?
                    .run_custom_function(EVAN_METHOD, "create_keys", "{}", "{}")
                    .await?
            }
            ("query_didcomm_messages", Some(sub_m)) => {
                let payload = get_argument_value(&sub_m, "payload", None);
                get_vade_evan(&sub_m)?
                    .run_custom_function(EVAN_METHOD, "query_didcomm_messages", "{}", &payload)
                    .await?
            }
            _ => {
                bail!("invalid subcommand");
            }
        },
        #[cfg(feature = "vc-zkp")]
        ("vc_zkp", Some(sub_m)) => match sub_m.subcommand() {
            #[cfg(feature = "vc-zkp-bbs")]
            ("create_credential_schema", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_create_credential_schema, sub_m)
            }
            #[cfg(feature = "vc-zkp-bbs")]
            ("create_master_secret", Some(sub_m)) => {
                let options = get_argument_value(sub_m, "options", None);
                get_vade_evan(&sub_m)?
                    .run_custom_function(EVAN_METHOD, "create_master_secret", options, "")
                    .await?
            }
            #[cfg(feature = "vc-zkp-bbs")]
            ("create_revocation_registry_definition", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_create_revocation_registry_definition, sub_m)
            }
            #[cfg(feature = "vc-zkp-bbs")]
            ("create_new_keys", Some(sub_m)) => {
                let payload = get_argument_value(sub_m, "payload", None);
                let options = get_argument_value(sub_m, "options", None);
                get_vade_evan(&sub_m)?
                    .run_custom_function(EVAN_METHOD, "create_new_keys", options, payload)
                    .await?
            }
            #[cfg(any(feature = "vc-zkp-bbs", feature = "jwt-vct"))]
            ("issue_credential", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_issue_credential, sub_m)
            }
            #[cfg(feature = "vc-zkp-bbs")]
            ("finish_credential", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_finish_credential, sub_m)
            }
            #[cfg(feature = "vc-zkp-bbs")]
            ("create_credential_offer", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_create_credential_offer, sub_m)
            }
            #[cfg(feature = "vc-zkp-bbs")]
            ("present_proof", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_present_proof, sub_m)
            }
            #[cfg(feature = "vc-zkp-bbs")]
            ("create_credential_proposal", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_create_credential_proposal, sub_m)
            }
            #[cfg(feature = "vc-zkp-bbs")]
            ("request_credential", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_request_credential, sub_m)
            }
            #[cfg(feature = "vc-zkp-bbs")]
            ("propose_proof", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_propose_proof, sub_m)
            }
            #[cfg(feature = "vc-zkp-bbs")]
            ("request_proof", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_request_proof, sub_m)
            }
            #[cfg(feature = "vc-zkp-bbs")]
            ("revoke_credential", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_revoke_credential, sub_m)
            }
            #[cfg(any(feature = "vc-zkp-bbs", feature = "jwt-vct"))]
            ("verify_proof", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_verify_proof, sub_m)
            }
            _ => {
                bail!("invalid subcommand");
            }
        },
        ("helper", Some(sub_m)) => match sub_m.subcommand() {
            #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
            ("create_credential_offer", Some(sub_m)) => {
                let use_valid_until = match get_optional_argument_value(sub_m, "use_valid_until") {
                    Some(value) => value.to_lowercase() == "true",
                    None => false,
                };
                let include_credential_status =
                    match get_optional_argument_value(sub_m, "include_credential_status") {
                        Some(value) => value.to_lowercase() == "true",
                        None => false,
                    };
                get_vade_evan(sub_m)?
                    .helper_create_credential_offer(
                        get_argument_value(sub_m, "schema_did", None),
                        use_valid_until,
                        get_argument_value(sub_m, "issuer_did", None),
                        include_credential_status,
                        get_argument_value(sub_m, "required_reveal_statements", None),
                        get_optional_argument_value(sub_m, "credential_values"),
                    )
                    .await?
            }
            #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
            ("create_credential_request", Some(sub_m)) => {
                get_vade_evan(sub_m)?
                    .helper_create_credential_request(
                        get_argument_value(sub_m, "issuer_public_key", None),
                        get_argument_value(sub_m, "bbs_secret", None),
                        get_argument_value(sub_m, "credential_offer", None),
                        get_argument_value(sub_m, "schema_did", None),
                    )
                    .await?
            }
            #[cfg(feature = "did-sidetree")]
            ("did_create", Some(sub_m)) => {
                get_vade_evan(sub_m)?
                    .helper_did_create(
                        get_optional_argument_value(sub_m, "bbs_public_key"),
                        get_optional_argument_value(sub_m, "signing_key"),
                        get_optional_argument_value(sub_m, "service_endpoint"),
                        get_optional_argument_value(sub_m, "update_key_did_create"),
                        get_optional_argument_value(sub_m, "recovery_key"),
                    )
                    .await?
            }
            #[cfg(feature = "did-sidetree")]
            ("did_update", Some(sub_m)) => {
                get_vade_evan(sub_m)?
                    .helper_did_update(
                        get_argument_value(sub_m, "did", None),
                        get_argument_value(sub_m, "operation", None),
                        get_argument_value(sub_m, "update_key", None),
                        get_argument_value(sub_m, "payload", None),
                    )
                    .await?
            }
            #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
            ("verify_credential", Some(sub_m)) => {
                get_vade_evan(sub_m)?
                    .helper_verify_credential(
                        get_argument_value(sub_m, "credential", None),
                        get_argument_value(sub_m, "master_secret", None),
                    )
                    .await?;
                "".to_string()
            }
            #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
            ("revoke_credential", Some(sub_m)) => {
                get_vade_evan(sub_m)?
                    .helper_revoke_credential(
                        get_argument_value(sub_m, "credential", None),
                        get_argument_value(sub_m, "update_key", None),
                        get_optional_argument_value(sub_m, "issuer_public_key_did"),
                        get_optional_argument_value(sub_m, "issuer_proving_key"),
                    )
                    .await?
            }
            #[cfg(all(feature = "vc-zkp-bbs"))]
            ("convert_credential_to_nquads", Some(sub_m)) => {
                get_vade_evan(sub_m)?
                    .helper_convert_credential_to_nquads(get_argument_value(
                        sub_m,
                        "credential",
                        None,
                    ))
                    .await?
            }
            #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
            ("create_self_issued_credential", Some(sub_m)) => {
                get_vade_evan(sub_m)?
                    .helper_create_self_issued_credential(
                        get_argument_value(sub_m, "schema_did", None),
                        get_argument_value(sub_m, "credential_subject", None),
                        get_argument_value(sub_m, "issuer_did", None),
                        get_optional_argument_value(sub_m, "exp_date"),
                    )
                    .await?
            }
            #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
            ("create_proof_proposal", Some(sub_m)) => {
                get_vade_evan(sub_m)?
                    .helper_create_proof_proposal(
                        get_argument_value(sub_m, "schema_did", None),
                        get_optional_argument_value(sub_m, "revealed_attributes"),
                    )
                    .await?
            }
            #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
            ("create_proof_request", Some(sub_m)) => {
                let proposal = get_optional_argument_value(sub_m, "proof_proposal");

                match proposal {
                    Some(value) => {
                        get_vade_evan(sub_m)?
                            .helper_create_proof_request_from_proposal(value)
                            .await?
                    }
                    None => {
                        get_vade_evan(sub_m)?
                            .helper_create_proof_request(
                                get_argument_value(sub_m, "schema_did", None),
                                get_optional_argument_value(sub_m, "revealed_attributes"),
                            )
                            .await?
                    }
                }
            }
            #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
            ("create_presentation", Some(sub_m)) => {
                get_vade_evan(sub_m)?
                    .helper_create_presentation(
                        get_argument_value(sub_m, "proof_request", None),
                        get_argument_value(sub_m, "credential", None),
                        get_argument_value(sub_m, "master_secret", None),
                        get_optional_argument_value(sub_m, "private_key"),
                        get_optional_argument_value(sub_m, "subject_did"),
                        get_optional_argument_value(sub_m, "revealed_attributes"),
                    )
                    .await?
            }
            #[cfg(all(feature = "vc-zkp-bbs"))]
            ("create_self_issued_presentation", Some(sub_m)) => {
                get_vade_evan(sub_m)?
                    .helper_create_self_issued_presentation(get_argument_value(
                        sub_m,
                        "unsigned_credential",
                        None,
                    ))
                    .await?
            }
            #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
            ("verify_presentation", Some(sub_m)) => {
                get_vade_evan(sub_m)?
                    .helper_verify_presentation(
                        get_argument_value(sub_m, "presentation", None),
                        get_argument_value(sub_m, "proof_request", None),
                    )
                    .await?
            }
            _ => {
                bail!("invalid subcommand");
            }
        },
        ("build_version", Some(sub_m)) => get_vade_evan(sub_m)?.get_version_info(),
        _ => {
            bail!("invalid subcommand");
        }
    };

    println!("{}", &result);

    Ok(())
}

// not included in all build variants
#[allow(dead_code)]
fn add_subcommand_helper<'a>(app: App<'a, 'a>) -> Result<App<'a, 'a>> {
    // variable might be needlessly mutable due to the following feature listing not matching
    #[allow(unused_mut)]
    let mut subcommand = SubCommand::with_name("helper")
        .about("streamlined and updated VADE API that will replace some of the current functions")
        .setting(AppSettings::DeriveDisplayOrder)
        .setting(AppSettings::SubcommandRequiredElseHelp);

    cfg_if::cfg_if! {
        if #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_credential_offer")
                    .about("Creates a `CredentialOffer` message. A `CredentialOffer` is sent by an issuer and is the response to a `CredentialProposal`. The `CredentialOffer` specifies which schema the issuer is capable and willing to use for credential issuance.")
                    .arg(get_clap_argument("schema_did")?)
                    .arg(get_clap_argument("use_valid_until")?)
                    .arg(get_clap_argument("issuer_did")?)
                    .arg(get_clap_argument("include_credential_status")?)
                    .arg(get_clap_argument("required_reveal_statements")?)
                    .arg(get_clap_argument("credential_values")?)
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_credential_request")
                    .about("Requests a credential. This message is the response to a credential offering and is sent by the potential credential holder. It incorporates the target schema, credential definition offered by the issuer, and the encoded values the holder wants to get signed. The credential is not stored on-chain and needs to be kept private.")
                    .arg(get_clap_argument("issuer_public_key")?)
                    .arg(get_clap_argument("bbs_secret")?)
                    .arg(get_clap_argument("credential_offer")?)
                    .arg(get_clap_argument("schema_did")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
            if #[cfg(feature = "did-sidetree")] {
                subcommand = subcommand.subcommand(
                    SubCommand::with_name("did_create")
                        .about("Creates a did, take optional arguments for predefined keys and service endpoints")
                        .arg(get_clap_argument("bbs_public_key")?)
                        .arg(get_clap_argument("signing_key")?)
                        .arg(get_clap_argument("service_endpoint")?)
                        .arg(get_clap_argument("update_key_did_create")?)
                        .arg(get_clap_argument("recovery_key")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                );
            } else {}
    }

    cfg_if::cfg_if! {
            if #[cfg(feature = "did-sidetree")] {
                subcommand = subcommand.subcommand(
                    SubCommand::with_name("did_update")
                        .about("Updates a did (add/remove publickey and add/remove service_endpoint)")
                        .arg(get_clap_argument("did")?)
                        .arg(get_clap_argument("operation")?)
                        .arg(get_clap_argument("update_key")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                );
            } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("verify_credential")
                    .about("Verifies a given credential by checking if given master secret was incorporated into proof and if proof was signed with issuers public key.")
                    .arg(get_clap_argument("credential")?)
                    .arg(get_clap_argument("master_secret")?)
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(all(feature = "vc-zkp-bbs"))] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("convert_credential_to_nquads")
                    .about("Converts a given credential to nquads vector.")
                    .arg(get_clap_argument("credential")?)
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("revoke_credential")
                    .about("Revokes a given credential with vade and updates the revocation list credential.")
                    .arg(get_clap_argument("credential")?)
                    .arg(get_clap_argument("update_key")?)
                    .arg(get_clap_argument("issuer_public_key_did")?)
                    .arg(get_clap_argument("issuer_proving_key")?)
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_self_issued_credential")
                    .about("Creates a self issued credential.")
                    .arg(get_clap_argument("schema_did")?)
                    .arg(get_clap_argument("credential_subject")?)
                    .arg(get_clap_argument("exp_date")?)
                    .arg(get_clap_argument("issuer_did")?)
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_proof_proposal")
                    .about("Proposes a proof for a credential.")
                    .arg(get_clap_argument("schema_did")?)
                    .arg(get_clap_argument("revealed_attributes")?)
            );
        } else {}
    }
    cfg_if::cfg_if! {
        if #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_proof_request")
                    .about("Requests a proof for a credential.")
                    .arg(get_clap_argument("schema_did_optional")?)
                    .arg(get_clap_argument("revealed_attributes")?)
                    .arg(get_clap_argument("proof_proposal")?)
            );
        } else {}
    }
    cfg_if::cfg_if! {
        if #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_presentation")
                    .about("Creates a presentation for a proof request.")
                    .arg(get_clap_argument("proof_request")?)
                    .arg(get_clap_argument("credential")?)
                    .arg(get_clap_argument("master_secret")?)
                    .arg(get_clap_argument("private_key")?)
                    .arg(get_clap_argument("subject_did")?)
                    .arg(get_clap_argument("revealed_attributes")?)
            );
        } else {}
    }
    cfg_if::cfg_if! {
        if #[cfg(all(feature = "vc-zkp-bbs"))] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_self_issued_presentation")
                    .about("Creates a self issued presentation.")
                    .arg(get_clap_argument("unsigned_credential")?)
            );
        } else {}
    }
    cfg_if::cfg_if! {
        if #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("verify_presentation")
                    .about("Verifies a presentation against a proof request.")
                    .arg(get_clap_argument("presentation")?)
                    .arg(get_clap_argument("proof_request")?)
            );
        } else {}
    }
    Ok(app.subcommand(subcommand))
}

// not included in all build variants
#[allow(dead_code)]
fn add_subcommand_did<'a>(app: App<'a, 'a>) -> Result<App<'a, 'a>> {
    // variable might be needlessly mutable due to the following feature listing not matching
    #[allow(unused_mut)]
    let mut subcommand = SubCommand::with_name("did")
        .about("Work with DIDs")
        .setting(AppSettings::DeriveDisplayOrder)
        .setting(AppSettings::SubcommandRequiredElseHelp);

    cfg_if::cfg_if! {
        if #[cfg(feature = "did-read")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("resolve")
                    .about("Fetch data about a DID, which returns this DID's DID document.")
                    .arg(get_clap_argument("did")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "did-read")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create")
                    .about("Creates a new DID.")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            )
            .subcommand(
                SubCommand::with_name("resolve")
                    .about("Fetch data about a DID, which returns this DID's DID document.")
                    .arg(get_clap_argument("did")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            )
            .subcommand(
                SubCommand::with_name("update")
                    .about(r###"Updates data related to a DID.`"###)
                    .arg(get_clap_argument("did")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            )
        } else {}
    }

    Ok(app.subcommand(subcommand))
}

// not included in all build variants
#[allow(dead_code)]
fn add_subcommand_didcomm<'a>(app: App<'a, 'a>) -> Result<App<'a, 'a>> {
    let app = app.subcommand(
        SubCommand::with_name("didcomm")
            .about("Process DIDComm message")
            .setting(AppSettings::DeriveDisplayOrder)
            .setting(AppSettings::SubcommandRequiredElseHelp)
            .subcommand(
                SubCommand::with_name("send")
                    .about(r###"Prepare a plain DIDComm json message to be sent, including encryption and protocol specific message enhancement. The DIDComm options can include a shared secret to encrypt the message with a specific key. If no key was given and the message should be encrypted (depends on protocol implementation), the DIDComm keypair from a db provider will be used."###)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?),
            )
            .subcommand(
                SubCommand::with_name("receive")
                    .about(r###"Receive a plain DIDComm json message, including decryption and protocol specific message parsing. The DIDComm options can include a shared secret to encrypt the message with a specific key. If no key was given and the message is encrypted the DIDComm keypair from a db will be used."###)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?),
            )
            .subcommand(
                SubCommand::with_name("create_keys")
                    .about(r###"Create X25519 secret/public keys, which can be used in options while sending and receiving DIDComm message."###)
            )
            .subcommand(
                SubCommand::with_name("query_didcomm_messages")
                    .about(r###"Query stored DIDComm messages by prefix (message_{thid}_*) or message id (message_{thid}_{msgid})."###)
                    .arg(get_clap_argument("payload")?),
            )
    );

    Ok(app)
}

// not included in all build variants
#[allow(dead_code)]
fn add_subcommand_vc_zkp<'a>(app: App<'a, 'a>) -> Result<App<'a, 'a>> {
    // variable might be needlessly mutable due to the following feature listing not matching
    #[allow(unused_mut)]
    let mut subcommand = SubCommand::with_name("vc_zkp")
        .about("Work with zero knowledge proof VCs")
        .setting(AppSettings::DeriveDisplayOrder)
        .setting(AppSettings::SubcommandRequiredElseHelp);

    cfg_if::cfg_if! {
        if #[cfg(feature = "vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_master_secret")
                    .about("Creates a new master secret.")
                    .arg(get_clap_argument("options")?)
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_new_keys")
                    .about("Creates a new key pair and stores it in the DID document.")
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_credential_schema")
                    .about("Creates a new zero-knowledge proof credential schema.")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_revocation_registry_definition")
                    .about("Creates a new revocation registry definition and stores it on-chain. The definition consists of a public and a private part. The public part holds the cryptographic material needed to create non-revocation proofs. The private part needs to reside with the registry owner and is used to revoke credentials")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(any(feature = "vc-zkp-bbs", feature = "jwt-vc"))] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("issue_credential")
                    .about("Issues a new credential.")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("finish_credential")
                    .about("Finishes a credential by incorporating the prover's master secret into the credential signature after issuance.")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_credential_offer")
                    .about("Creates a `CredentialOffer` message. A `CredentialOffer` is sent by an issuer and is the response to a `CredentialProposal`. The `CredentialOffer` specifies which schema the issuer is capable and willing to use for credential issuance.")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("present_proof")
                    .about("Presents a proof for one or more credentials. A proof presentation is the response to a proof request. The proof needs to incorporate all required fields from all required schemas requested in the proof request.")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_credential_proposal")
                    .about("Creates a new zero-knowledge proof credential proposal. This message is the first in the credential issuance flow and is sent by the potential credential holder to the credential issuer.")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }
    cfg_if::cfg_if! {
        if #[cfg(feature = "vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("request_credential")
                    .about("Requests a credential. This message is the response to a credential offering and is sent by the potential credential holder. It incorporates the target schema offered by the issuer, and the encoded values the holder wants to get signed. The credential is not stored on-chain and needs to be kept private.")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("propose_proof")
                    .about("Proposes a zero-knowledge proof for one or more credentials issued under one or more specific schemas and is sent by a verifier to a prover. The proof proposal consists of the fields the verifier wants to be revealed per schema and can be used as input for a proof request.")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("request_proof")
                    .about("Requests a zero-knowledge proof for one or more credentials issued under one or more specific schemas and is sent by a verifier to a prover. The proof request consists of the fields the verifier wants to be revealed per schema.")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("revoke_credential")
                    .about("Revokes a credential. After revocation the published revocation registry needs to be updated with information returned by this function. To revoke a credential, tbe revoker must be in possession of the private key associated with the credential's revocation registry. After revocation, the published revocation registry must be updated. Only then is the credential truly revoked.")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(any(feature = "vc-zkp-bbs", feature = "jwt-vc"))] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("verify_proof")
                    .about("Verifies a one or multiple proofs sent in a proof presentation.")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
                    .arg(get_clap_argument("payload")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
            );
        } else {}
    }

    Ok(app.subcommand(subcommand))
}

fn get_app<'a>() -> Result<App<'a, 'a>> {
    // variable might be needlessly mutable due to the following feature listing not matching
    #[allow(unused_mut)]
    let mut app = App::new("vade_evan_cli")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("Allows to work with DIDs and zero knowledge proof VCs")
        .setting(AppSettings::DeriveDisplayOrder)
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("build_version")
                .about("shows version of vade_evan_cli build and its vade dependencies")
                .setting(AppSettings::DeriveDisplayOrder),
        );

    cfg_if::cfg_if! {
        if #[cfg(any(feature = "did-read", feature = "did-write"))] {
            app = add_subcommand_did(app)?;
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "didcomm")] {
            app = add_subcommand_didcomm(app)?;
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "vc-zkp")] {
            app = add_subcommand_vc_zkp(app)?;
        } else {}
    }

    app = add_subcommand_helper(app)?;

    Ok(app)
}

fn get_argument_matches<'a>() -> Result<ArgMatches<'a>> {
    Ok(get_app()?.get_matches())
}

fn get_argument_value<'a>(
    matches: &'a ArgMatches,
    arg_name: &'a str,
    fallback: Option<&'a str>,
) -> &'a str {
    match matches.value_of(arg_name) {
        Some(value) => value,
        None => match fallback {
            Some(value) => value,
            None => {
                panic!("no value for {} given", arg_name);
            }
        },
    }
}

#[cfg(any(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
fn get_optional_argument_value<'a>(matches: &'a ArgMatches, arg_name: &'a str) -> Option<&'a str> {
    matches.value_of(arg_name)
}

fn get_vade_evan(matches: &ArgMatches) -> Result<VadeEvan> {
    let target = get_argument_value(&matches, "target", Some(DEFAULT_TARGET));
    let signer = get_argument_value(&matches, "signer", Some(DEFAULT_SIGNER));
    return Ok(VadeEvan::new(VadeEvanConfig { target, signer })?);
}

fn get_clap_argument(arg_name: &str) -> Result<Arg> {
    Ok(match arg_name {
        "did" => Arg::with_name("did")
            .long("did")
            .short("d")
            .value_name("did")
            .required(true)
            .help("a DID to work with, e.g. 'did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906'")
            .takes_value(true),
        "method" => Arg::with_name("method")
            .long("method")
            .short("m")
            .value_name("method")
            .required(true)
            .help("method to use, e.g. 'did:evan'")
            .takes_value(true),
        "options" => Arg::with_name("options")
            .long("options")
            .short("o")
            .value_name("options")
            .required(true)
            .help("options to send to vade call, serialized JSON, e.g. '{ \"identity\": \"...\", \"privateKey\": \"...\" }'")
            .takes_value(true),
        "payload" => Arg::with_name("payload")
            .long("payload")
            .short("p")
            .value_name("payload")
            .required(true)
            .help("payload to send to vade call, serialized JSON, e.g. '{ \"foo\": \"bar\" }'")
            .takes_value(true),
        "target" => Arg::with_name("target")
            .long("target")
            .short("t")
            .value_name("target")
            .help("server to use for DID handling, e.g. '127.0.0.1'")
            .takes_value(true),
        "signer" => Arg::with_name("signer")
            .long("signer")
            .short("s")
            .value_name("signer")
            .help("signer to use to sign messages with, e.g. 'local' or 'remote|http://somewhere'")
            .takes_value(true),
        "issuer_public_key" => Arg::with_name("issuer_public_key")
            .long("issuer_public_key")
            .value_name("issuer_public_key")
            .required(true)
            .help("issuer public key")
            .takes_value(true),
        "credential_offer" => Arg::with_name("credential_offer")
            .long("credential_offer")
            .value_name("credential_offer")
            .required(true)
            .help("JSON string with credential offer by issuer")
            .takes_value(true),
        "credential_values" => Arg::with_name("credential_values")
            .long("credential_values")
            .value_name("credential_values")
            .required(false)
            .help("JSON string with cleartext values to be signed in the credential")
            .takes_value(true),
        "bbs_secret" => Arg::with_name("bbs_secret")
            .long("bbs_secret")
            .required(true)
            .value_name("bbs_secret")
            .help("master secret of the holder/receiver"),
        "schema_did" => Arg::with_name("schema_did")
            .long("schema_did")
            .value_name("schema_did")
            .required(true)
            .help("schema to create the offer for, e.g. 'did:evan:EiACv4q04NPkNRXQzQHOEMa3r1p_uINgX75VYP2gaK5ADw'")
            .takes_value(true),
        "schema_did_optional" => Arg::with_name("schema_did")
            .long("schema_did")
            .value_name("schema_did")
            .help("schema to create the offer for, e.g. 'did:evan:EiACv4q04NPkNRXQzQHOEMa3r1p_uINgX75VYP2gaK5ADw'")
            .takes_value(true),
        "use_valid_until" => Arg::with_name("use_valid_until")
            .long("use_valid_until")
            .value_name("use_valid_until")
            .help("true if `validUntil` will be present in credential")
            .takes_value(true),
        "include_credential_status" => Arg::with_name("include_credential_status")
            .long("include_credential_status")
            .value_name("include_credential_status")
            .required(true)
            .help("true if `credential_status` will be present in credential")
            .takes_value(true),
        "issuer_did" => Arg::with_name("issuer_did")
            .long("issuer_did")
            .value_name("issuer_did")
            .required(true)
            .help("DID of issuer")
            .takes_value(true),
        "subject_did" => Arg::with_name("subject_did")
            .long("subject_did")
            .value_name("subject_did")
            .required(true)
            .help("DID of subject/holder/prover")
            .takes_value(true),
        "credential_subject" => Arg::with_name("credential_subject") // same as above, but mandatory
            .long("credential_subject")
            .value_name("credential_subject")
            .required(true)
            .help("DID of subject")
            .takes_value(true),
        "operation" => Arg::with_name("operation")
            .long("operation")
            .value_name("operation")
            .required(true)
            .help("Operation type AddKey/RemoveKey/AddServiceEndpoint/RemoveServiceEndpoint")
            .takes_value(true),
        "update_key" => Arg::with_name("update_key")
            .long("update_key")
            .value_name("update_key")
            .required(true)
            .help("Update key for did update in JWK format")
            .takes_value(true),
        "update_key_did_create" => Arg::with_name("update_key_did_create")
            .long("update_key_did_create")
            .value_name("update_key_did_create")
            .help("Optional Update key for did create in JWK format")
            .takes_value(true),
        "recovery_key" => Arg::with_name("recovery_key")
            .long("recovery_key")
            .value_name("recovery_key")
            .help("Recovery key for did in JWK format")
            .takes_value(true),
        "bbs_public_key" => Arg::with_name("bbs_public_key")
            .long("bbs_public_key")
            .value_name("bbs_public_key")
            .help("optional pre-generated bbs public key")
            .takes_value(true),
        "signing_key" => Arg::with_name("signing_key")
            .long("signing_key")
            .value_name("signing_key")
            .help("optional signing key to be added to did doc")
            .takes_value(true),
        "service_endpoint" => Arg::with_name("service_endpoint")
            .long("service_endpoint")
            .value_name("optional service_endpoint to be added to did doc")
            .help("Service endpoint url"),
        "credential" => Arg::with_name("credential")
            .long("credential")
            .value_name("credential")
            .required(true)
            .help("credential to verity")
            .takes_value(true),
        "unsigned_credential" => Arg::with_name("unsigned_credential")
            .long("unsigned_credential")
            .value_name("unsigned_credential")
            .required(true)
            .help("Credential without proof")
            .takes_value(true),
        "master_secret" => Arg::with_name("master_secret")
            .long("master_secret")
            .value_name("master_secret")
            .required(true)
            .help("master secret incorporated as a blinded value into the proof of the credential")
            .takes_value(true),
        "private_key" => Arg::with_name("private_key")
            .long("private_key")
            .value_name("private_key")
            .required(true)
            .help("private key to be supplied for local signer")
            .takes_value(true),
        "issuer_public_key_did" => Arg::with_name("issuer_public_key_did")
            .long("issuer_public_key_did")
            .value_name("issuer_public_key_did")
            .help("public key used for assertion proofs")
            .takes_value(true),
        "issuer_proving_key" => Arg::with_name("issuer_proving_key")
            .long("issuer_proving_key")
            .value_name("issuer_proving_key")
            .help("private key used for assertion proofs")
            .takes_value(true),
        "credential_revocation_did" => Arg::with_name("credential_revocation_did")
            .long("credential_revocation_did")
            .value_name("credential_revocation_did")
            .help("revocation list DID")
            .takes_value(true),
        "credential_revocation_id" => Arg::with_name("credential_revocation_id")
            .long("credential_revocation_id")
            .value_name("credential_revocation_id")
            .help("index in revocation list")
            .takes_value(true),
        "exp_date" => Arg::with_name("exp_date")
            .long("exp_date")
            .value_name("exp_date")
            .required(false)
            .help(r#"expiration date, string, e.g. "1722-12-03T14:23:42.120Z""#)
            .takes_value(true),
        "revealed_attributes" => Arg::with_name("revealed_attributes")
            .long("revealed_attributes")
            .value_name("revealed_attributes")
            .help("list of names of revealed attributes in specified schema, reveals all if omitted")
            .takes_value(true),
        "required_reveal_statements" => Arg::with_name("required_reveal_statements")
            .long("required_reveal_statements")
            .value_name("required_reveal_statements")
            .help("list of indices to be made as revealed mandatorily in credential presentation")
            .takes_value(true)
            .required(true),
        "proof_proposal" => Arg::with_name("proof_proposal")
            .long("proof_proposal")
            .value_name("proof_proposal")
            .help("bbs proof proposal for presentation sharing")
            .takes_value(true),
        "proof_request" => Arg::with_name("proof_request")
            .long("proof_request")
            .value_name("proof_request")
            .required(true)
            .help("bbs proof request for presentation sharing")
            .takes_value(true),
        "presentation" => Arg::with_name("presentation")
            .long("presentation")
            .value_name("presentation")
            .required(true)
            .help("bbs presentation")
            .takes_value(true),
        _ => {
            bail!("invalid arg_name: '{}'", &arg_name);
        },
    })
}
