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

#[cfg(any(feature = "capability-didcomm", feature = "plugin-vc-zkp-bbs"))]
const EVAN_METHOD: &str = "did:evan";

#[tokio::main]
async fn main() -> Result<()> {
    let matches = get_argument_matches()?;

    let result = match matches.subcommand() {
        #[cfg(any(feature = "capability-did-read", feature = "capability-did-write"))]
        ("did", Some(sub_m)) => match sub_m.subcommand() {
            #[cfg(feature = "capability-did-write")]
            ("create", Some(sub_m)) => {
                let method = get_argument_value(&sub_m, "method", None);
                let options = get_argument_value(&sub_m, "options", None);
                get_vade_evan(&sub_m)?
                    .did_create(&method, &options, &String::new())
                    .await?
            }
            #[cfg(feature = "capability-did-read")]
            ("resolve", Some(sub_m)) => {
                let did = get_argument_value(&sub_m, "did", None);
                get_vade_evan(&sub_m)?.did_resolve(&did).await?
            }
            #[cfg(feature = "capability-did-write")]
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
        #[cfg(feature = "capability-didcomm")]
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
        #[cfg(feature = "capability-vc-zkp")]
        ("vc_zkp", Some(sub_m)) => match sub_m.subcommand() {
            #[cfg(feature = "plugin-vc-zkp-bbs")]
            ("create_credential_schema", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_create_credential_schema, sub_m)
            }
            #[cfg(feature = "plugin-vc-zkp-bbs")]
            ("create_master_secret", Some(sub_m)) => {
                let options = get_argument_value(sub_m, "options", None);
                get_vade_evan(&sub_m)?
                    .run_custom_function(EVAN_METHOD, "create_master_secret", options, "")
                    .await?
            }
            #[cfg(feature = "plugin-vc-zkp-bbs")]
            ("create_revocation_registry_definition", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_create_revocation_registry_definition, sub_m)
            }
            #[cfg(feature = "plugin-vc-zkp-bbs")]
            ("create_new_keys", Some(sub_m)) => {
                let payload = get_argument_value(sub_m, "payload", None);
                let options = get_argument_value(sub_m, "options", None);
                get_vade_evan(&sub_m)?
                    .run_custom_function(EVAN_METHOD, "create_new_keys", options, payload)
                    .await?
            }
            #[cfg(any(feature = "plugin-vc-zkp-bbs", feature = "plugin-jwt-vct"))]
            ("issue_credential", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_issue_credential, sub_m)
            }
            #[cfg(feature = "plugin-vc-zkp-bbs")]
            ("finish_credential", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_finish_credential, sub_m)
            }
            #[cfg(feature = "plugin-vc-zkp-bbs")]
            ("create_credential_offer", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_create_credential_offer, sub_m)
            }
            #[cfg(feature = "plugin-vc-zkp-bbs")]
            ("present_proof", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_present_proof, sub_m)
            }
            #[cfg(feature = "plugin-vc-zkp-bbs")]
            ("create_credential_proposal", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_create_credential_proposal, sub_m)
            }
            #[cfg(feature = "plugin-vc-zkp-bbs")]
            ("request_credential", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_request_credential, sub_m)
            }
            #[cfg(feature = "plugin-vc-zkp-bbs")]
            ("request_proof", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_request_proof, sub_m)
            }
            #[cfg(feature = "plugin-vc-zkp-bbs")]
            ("revoke_credential", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_revoke_credential, sub_m)
            }
            #[cfg(any(feature = "plugin-vc-zkp-bbs", feature = "plugin-jwt-vct"))]
            ("verify_proof", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_verify_proof, sub_m)
            }
            _ => {
                bail!("invalid subcommand");
            }
        },
        ("helper", Some(sub_m)) => match sub_m.subcommand() {
            #[cfg(feature = "plugin-vc-zkp-bbs")]
            ("create_credential_offer", Some(sub_m)) => {
                let use_valid_until = match get_optional_argument_value(sub_m, "use_valid_until") {
                    Some(value) => value.to_lowercase() == "true",
                    None => false,
                };
                get_vade_evan(sub_m)?
                    .helper_create_credential_offer(
                        get_argument_value(sub_m, "schema_did", None),
                        use_valid_until,
                        get_argument_value(sub_m, "issuer_did", None),
                        get_optional_argument_value(sub_m, "subject_did"),
                    )
                    .await?
            }
            #[cfg(feature = "plugin-vc-zkp-bbs")]
            ("create_credential_request", Some(sub_m)) => {
                get_vade_evan(sub_m)?
                    .helper_create_credential_request(
                        get_argument_value(sub_m, "issuer_public_key", None),
                        get_argument_value(sub_m, "bbs_secret", None),
                        get_argument_value(sub_m, "credential_values", None),
                        get_argument_value(sub_m, "credential_offer", None),
                        get_argument_value(sub_m, "schema_did", None),
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
        if #[cfg(feature = "plugin-vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_credential_offer")
                    .about("Creates a `CredentialOffer` message. A `CredentialOffer` is sent by an issuer and is the response to a `CredentialProposal`. The `CredentialOffer` specifies which schema the issuer is capable and willing to use for credential issuance.")
                    .arg(get_clap_argument("schema_did")?)
                    .arg(get_clap_argument("use_valid_until")?)
                    .arg(get_clap_argument("issuer_did")?)
                    .arg(get_clap_argument("subject_did")?),
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "plugin-vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_credential_request")
                    .about("Requests a credential. This message is the response to a credential offering and is sent by the potential credential holder. It incorporates the target schema, credential definition offered by the issuer, and the encoded values the holder wants to get signed. The credential is not stored on-chain and needs to be kept private.")
                    .arg(get_clap_argument("issuer_public_key")?)
                    .arg(get_clap_argument("bbs_secret")?)
                    .arg(get_clap_argument("credential_values")?)
                    .arg(get_clap_argument("credential_offer")?)
                    .arg(get_clap_argument("schema_did")?)
                    .arg(get_clap_argument("target")?)
                    .arg(get_clap_argument("signer")?),
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
        if #[cfg(feature = "capability-did-read")] {
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
        if #[cfg(feature = "capability-did-read")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create")
                    .about("Creates a new DID.")
                    .arg(get_clap_argument("method")?)
                    .arg(get_clap_argument("options")?)
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
        if #[cfg(feature = "plugin-vc-zkp-bbs")] {
            subcommand = subcommand.subcommand(
                SubCommand::with_name("create_master_secret")
                    .about("Creates a new master secret.")
                    .arg(get_clap_argument("options")?)
            );
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "plugin-vc-zkp-bbs")] {
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
        if #[cfg(feature = "plugin-vc-zkp-bbs")] {
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
        if #[cfg(feature = "plugin-vc-zkp-bbs")] {
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
        if #[cfg(any(feature = "plugin-vc-zkp-bbs", feature = "plugin-jwt-vct"))] {
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
        if #[cfg(feature = "plugin-vc-zkp-bbs")] {
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
        if #[cfg(feature = "plugin-vc-zkp-bbs")] {
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
        if #[cfg(feature = "plugin-vc-zkp-bbs")] {
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
        if #[cfg(feature = "plugin-vc-zkp-bbs")] {
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
        if #[cfg(feature = "plugin-vc-zkp-bbs")] {
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
        if #[cfg(feature = "plugin-vc-zkp-bbs")] {
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
        if #[cfg(feature = "plugin-vc-zkp-bbs")] {
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
        if #[cfg(any(feature = "plugin-vc-zkp-bbs", feature = "plugin-jwt-vct"))] {
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
        if #[cfg(any(feature = "capability-did-read", feature = "capability-did-write"))] {
            app = add_subcommand_did(app)?;
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "capability-didcomm")] {
            app = add_subcommand_didcomm(app)?;
        } else {}
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "capability-vc-zkp")] {
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

#[cfg(feature = "plugin-vc-zkp-bbs")] // currently only used for vc offers
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
            .help("issuer public key")
            .takes_value(true),
        "credential_offer" => Arg::with_name("credential_offer")
            .long("credential_offer")
            .value_name("credential_offer")
            .help("JSON string with credential offer by issuer")
            .takes_value(true),
        "credential_values" => Arg::with_name("credential_values")
            .long("credential_values")
            .value_name("credential_values")
            .help("JSON string with cleartext values to be signed in the credential")
            .takes_value(true),
        "bbs_secret" => Arg::with_name("bbs_secret")
            .long("bbs_secret")
            .value_name("bbs_secret")
            .help("master secret of the holder/receiver"),
        "schema_did" => Arg::with_name("schema_did")
            .long("schema_did")
            .value_name("schema_did")
            .required(true)
            .help("schema to create the offer for, e.g. 'did:evan:EiACv4q04NPkNRXQzQHOEMa3r1p_uINgX75VYP2gaK5ADw'")
            .takes_value(true),
        "use_valid_until" => Arg::with_name("use_valid_until")
            .long("use_valid_until")
            .value_name("use_valid_until")
            .help("true if `validUntil` will be present in credential")
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
            .help("DID of subject")
            .takes_value(true),
        _ => {
            bail!("invalid arg_name: '{}'", &arg_name);
        },
    })
}
