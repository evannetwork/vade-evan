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

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use std::error::Error;
use vade::Vade;
use vade_evan_cl::VadeEvanCl;
use vade_evan_substrate::{
    signing::{LocalSigner, RemoteSigner, Signer},
    ResolverConfig,
    VadeEvanSubstrate,
};

macro_rules! wrap_vade3 {
    ($func_name:ident, $sub_m:ident) => {{
        let method = get_argument_value($sub_m, "method", None);
        let options = get_argument_value($sub_m, "options", None);
        let payload = get_argument_value($sub_m, "payload", None);
        get_vade($sub_m)?
            .$func_name(&method, &options, &payload)
            .await?
    }};
}

const EVAN_METHOD: &str = "did:evan";
const TYPE_OPTIONS_CL: &str = r###"{ "type": "cl" }"###;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = get_argument_matches()?;

    let results = match matches.subcommand() {
        ("did", Some(sub_m)) => match sub_m.subcommand() {
            ("create", Some(sub_m)) => {
                let did = get_argument_value(&sub_m, "did", None);
                let options = get_argument_value(&sub_m, "options", None);
                get_vade(&sub_m)?
                    .did_create(&did, &options, &String::new())
                    .await?
            }
            ("resolve", Some(sub_m)) => {
                let did = get_argument_value(&sub_m, "did", None);
                get_vade(&sub_m)?.did_resolve(&did).await?
            }
            ("update", Some(sub_m)) => {
                wrap_vade3!(did_update, sub_m)
            }
            _ => {
                return Err(Box::from(clap::Error::with_description(
                    "invalid subcommand",
                    clap::ErrorKind::InvalidSubcommand,
                )));
            }
        },
        ("vc_zkp", Some(sub_m)) => match sub_m.subcommand() {
            ("create_credential_definition", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_create_credential_definition, sub_m)
            }
            ("create_credential_schema", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_create_credential_schema, sub_m)
            }
            ("create_master_secret", Some(sub_m)) => {
                get_vade(&sub_m)?
                    .run_custom_function(EVAN_METHOD, "create_master_secret", TYPE_OPTIONS_CL, "")
                    .await?
            }
            ("create_revocation_registry_definition", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_create_revocation_registry_definition, sub_m)
            }
            ("generate_safe_prime", Some(sub_m)) => {
                get_vade(&sub_m)?
                    .run_custom_function(EVAN_METHOD, "generate_safe_prime", TYPE_OPTIONS_CL, "")
                    .await?
            }
            ("issue_credential", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_issue_credential, sub_m)
            }
            ("finish_credential", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_finish_credential, sub_m)
            }
            ("create_credential_offer", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_create_credential_offer, sub_m)
            }
            ("present_proof", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_present_proof, sub_m)
            }
            ("create_credential_proposal", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_create_credential_proposal, sub_m)
            }
            ("request_credential", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_request_credential, sub_m)
            }
            ("request_proof", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_request_proof, sub_m)
            }
            ("revoke_credential", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_revoke_credential, sub_m)
            }
            ("verify_proof", Some(sub_m)) => {
                wrap_vade3!(vc_zkp_verify_proof, sub_m)
            }
            _ => {
                return Err(Box::from(clap::Error::with_description(
                    "invalid subcommand",
                    clap::ErrorKind::InvalidSubcommand,
                )));
            }
        },
        _ => {
            return Err(Box::from(clap::Error::with_description(
                "invalid subcommand",
                clap::ErrorKind::InvalidSubcommand,
            )));
        }
    };
    if results.is_empty() {
        panic!("no results");
    }

    let empty_result = String::new();
    let result_string = results[0]
        .as_ref()
        .or(Some(&empty_result))
        .unwrap()
        .to_string();

    println!("{}", &result_string);

    Ok(())
}

fn get_argument_matches() -> Result<ArgMatches<'static>, Box<dyn Error>> {
    Ok(App::new("vade_evan_bin")
        .version("0.0.6")
        .author("evan GmbH")
        .about("Allows you to use to work with DIDs and zero knowledge proof VCs on Trust and Trace")
        .setting(AppSettings::DeriveDisplayOrder)
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("did")
                .about("Works with DIDs on TRUST & TRACE.")
                .setting(AppSettings::DeriveDisplayOrder)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("create")
                        .about("Creates a new DID on substrate.")
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
                        .about(r###"Updates data related to a DID. Two updates are supported depending on the value of `options.operation`.
            - whitelistIdentity: whitelists identity `did` on substrate, this is required to be able to perform transactions this this identity
            - setDidDocument: sets the DID document for `did`"###)
                        .arg(get_clap_argument("did")?)
                        .arg(get_clap_argument("options")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                )
        )
        .subcommand(
            SubCommand::with_name("vc_zkp")
                .about("Works with zero knowledge proof VCs on TRUST & TRACE.")
                .setting(AppSettings::DeriveDisplayOrder)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("create_master_secret")
                        .about("Creates a new master secret.")
                )
                .subcommand(
                    SubCommand::with_name("generate_safe_prime")
                        .about("Generates a new safe prime number, that can be used in combination with `create_credential_definition` to for key pair generation.")
                )
                .subcommand(
                    SubCommand::with_name("create_credential_definition")
                        .about("Creates a new credential definition and stores the public part on-chain. The private part (key) needs to be stored in a safe way and must not be shared. A credential definition holds cryptographic material needed to verify proofs. Every definition is bound to one credential schema. Note that `options.identity` needs to be whitelisted for this function.")
                        .arg(get_clap_argument("method")?)
                        .arg(get_clap_argument("options")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("create_credential_schema")
                        .about("Creates a new zero-knowledge proof credential schema. Note that `options.identity` needs to be whitelisted for this function.")
                        .arg(get_clap_argument("method")?)
                        .arg(get_clap_argument("options")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("create_revocation_registry_definition")
                        .about("Creates a new revocation registry definition and stores it on-chain. The definition consists of a public and a private part. The public part holds the cryptographic material needed to create non-revocation proofs. The private part needs to reside with the registry owner and is used to revoke credentials. Note that `options.identity` needs to be whitelisted for this function.")
                        .arg(get_clap_argument("method")?)
                        .arg(get_clap_argument("options")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("issue_credential")
                        .about("Finishes a credential by incorporating the prover's master secret into the credential signature after issuance.")
                        .arg(get_clap_argument("method")?)
                        .arg(get_clap_argument("options")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("finish_credential")
                        .about("Issues a new credential. This requires an issued schema, credential definition, an active revocation registry and a credential request message.")
                        .arg(get_clap_argument("method")?)
                        .arg(get_clap_argument("options")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("create_credential_offer")
                        .about("Creates a `CredentialOffer` message. A `CredentialOffer` is sent by an issuer and is the response to a `CredentialProposal`. The `CredentialOffer` specifies which schema and definition the issuer is capable and willing to use for credential issuance.")
                        .arg(get_clap_argument("method")?)
                        .arg(get_clap_argument("options")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("present_proof")
                        .about("Presents a proof for one or more credentials. A proof presentation is the response to a proof request. The proof needs to incorporate all required fields from all required schemas requested in the proof request.")
                        .arg(get_clap_argument("method")?)
                        .arg(get_clap_argument("options")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("create_credential_proposal")
                        .about("Creates a new zero-knowledge proof credential proposal. This message is the first in the credential issuance flow and is sent by the potential credential holder to the credential issuer.")
                        .arg(get_clap_argument("method")?)
                        .arg(get_clap_argument("options")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("request_credential")
                        .about("Requests a credential. This message is the response to a credential offering and is sent by the potential credential holder. It incorporates the target schema, credential definition offered by the issuer, and the encoded values the holder wants to get signed. The credential is not stored on-chain and needs to be kept private.")
                        .arg(get_clap_argument("method")?)
                        .arg(get_clap_argument("options")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("request_proof")
                        .about("Requests a zero-knowledge proof for one or more credentials issued under one or more specific schemas and is sent by a verifier to a prover. The proof request consists of the fields the verifier wants to be revealed per schema.")
                        .arg(get_clap_argument("method")?)
                        .arg(get_clap_argument("options")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("revoke_credential")
                        .about("Revokes a credential. After revocation the published revocation registry needs to be updated with information returned by this function. To revoke a credential, tbe revoker must be in possession of the private key associated with the credential's revocation registry. After revocation, the published revocation registry must be updated. Only then is the credential truly revoked. Note that `options.identity` needs to be whitelisted for this function.")
                        .arg(get_clap_argument("method")?)
                        .arg(get_clap_argument("options")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("verify_proof")
                        .about("Verifies a one or multiple proofs sent in a proof presentation.")
                        .arg(get_clap_argument("method")?)
                        .arg(get_clap_argument("options")?)
                        .arg(get_clap_argument("payload")?)
                        .arg(get_clap_argument("target")?)
                        .arg(get_clap_argument("signer")?),
                )
        )
        .get_matches())
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

fn get_clap_argument(arg_name: &str) -> Result<Arg, Box<dyn Error>> {
    Ok(match arg_name {
        "did" => Arg::with_name("did")
            .long("did")
            .short("d")
            .value_name("did")
            .required(true)
            .help("a DID to work on, e.g. 'did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906'")
            .takes_value(true),
        "method" => Arg::with_name("method")
            .long("method")
            .short("m")
            .value_name("method")
            .required(true)
            .help("method to work on, e.g. 'did:evan'")
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
            .help("options to send to vade call, serialized JSON, e.g. '{ \"foo\": \"bar\" }'")
            .takes_value(true),
        "target" => Arg::with_name("target")
            .long("target")
            .short("t")
            .value_name("target")
            .help("substrate to use for DID handling, e.g. '127.0.0.1'")
            .takes_value(true),
        "signer" => Arg::with_name("signer")
            .long("signer")
            .short("s")
            .value_name("signer")
            .help("signer to use to sign messages with, e.g. 'local' or 'remote|http://somewhere'")
            .takes_value(true),
        _ => {
            return Err(Box::from(format!("invalid arg_name: '{}'", &arg_name)));
        },
    })
}

fn get_signer(signer: &str) -> Box<dyn Signer> {
    if signer.starts_with("remote") {
        Box::new(RemoteSigner::new(
            signer.trim_start_matches("remote|").to_string(),
        ))
    } else if signer.starts_with("local") {
        Box::new(LocalSigner::new())
    } else {
        panic!("invalid signer config")
    }
}

fn get_vade(matches: &ArgMatches<'static>) -> Result<Vade, Box<dyn Error>> {
    let target = get_argument_value(&matches, "target", Some("13.69.59.185"));
    let signer = get_argument_value(&matches, "signer", Some("local"));

    let mut vade = Vade::new();

    let signer_box: Box<dyn Signer> = get_signer(signer);

    vade.register_plugin(Box::from(VadeEvanSubstrate::new(ResolverConfig {
        signer: signer_box,
        target: target.to_string(),
    })));

    vade.register_plugin(Box::from(get_vade_evan_cl(target, signer)?));

    Ok(vade)
}

fn get_vade_evan_cl(target: &str, signer: &str) -> Result<VadeEvanCl, Box<dyn Error>> {
    let mut internal_vade = Vade::new();
    let signer_box: Box<dyn Signer> = get_signer(signer);
    internal_vade.register_plugin(Box::from(VadeEvanSubstrate::new(ResolverConfig {
        signer: signer_box,
        target: target.to_string(),
    })));
    let signer: Box<dyn Signer> = get_signer(signer);

    Ok(VadeEvanCl::new(internal_vade, signer))
}
