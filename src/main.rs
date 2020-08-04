extern crate clap;
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use ursa::cl::prover::Prover;
use vade::Vade;
use vade_evan::{
    resolver::{ResolverConfig, SubstrateDidResolverEvan},
    signing::{LocalSigner, RemoteSigner, Signer},
    VadeEvan,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = get_args()?;

    let results = match matches.subcommand() {
        ("did", Some(sub_m)) => match sub_m.subcommand() {
            ("create", Some(sub_m)) => {
                let did = get_arg(&sub_m, "did", None);
                let options = get_arg(&sub_m, "options", None);
                get_vade(&sub_m)?.did_create(&did, &options, &String::new()).await?
            }
            ("resolve", Some(sub_m)) => {
                let did = get_arg(&sub_m, "did", None);
                get_vade(&sub_m)?.did_resolve(&did).await?
            }
            ("update", Some(sub_m)) => {
                let did = get_arg(&sub_m, "did", None);
                let options = get_arg(&sub_m, "options", None);
                let payload = get_arg(&sub_m, "payload", None);
                get_vade(&sub_m)?.did_update(&did, &options, &payload).await?
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
                let method = get_arg(&sub_m, "method", None);
                let options = get_arg(&sub_m, "options", None);
                let payload = get_arg(&sub_m, "payload", None);
                get_vade(&sub_m)?.vc_zkp_create_credential_definition(&method, &options, &payload)
                    .await?
            }
            ("create_credential_schema", Some(sub_m)) => {
                let method = get_arg(&sub_m, "method", None);
                let options = get_arg(&sub_m, "options", None);
                let payload = get_arg(&sub_m, "payload", None);
                get_vade(&sub_m)?.vc_zkp_create_credential_schema(&method, &options, &payload)
                    .await?
            }
            ("create_master_secret", Some(_)) => vec![Some(serde_json::to_string(
                &Prover::new_master_secret().map_err(|_| "could not create master secret")?,
            )?)],
            ("create_revocation_registry_definition", Some(sub_m)) => {
                let method = get_arg(&sub_m, "method", None);
                let options = get_arg(&sub_m, "options", None);
                let payload = get_arg(&sub_m, "payload", None);
                get_vade(&sub_m)?.vc_zkp_create_revocation_registry_definition(&method, &options, &payload)
                    .await?
            }
            ("issue_credential", Some(sub_m)) => {
                let method = get_arg(&sub_m, "method", None);
                let payload = get_arg(&sub_m, "payload", None);
                get_vade(&sub_m)?.vc_zkp_issue_credential(&method, "", &payload).await?
            }
            ("create_credential_offer", Some(sub_m)) => {
                let method = get_arg(&sub_m, "method", None);
                let payload = get_arg(&sub_m, "payload", None);
                get_vade(&sub_m)?.vc_zkp_create_credential_offer(&method, "", &payload)
                    .await?
            }
            ("present_proof", Some(sub_m)) => {
                let method = get_arg(&sub_m, "method", None);
                let payload = get_arg(&sub_m, "payload", None);
                get_vade(&sub_m)?.vc_zkp_present_proof(&method, "", &payload).await?
            }
            ("create_credential_proposal", Some(sub_m)) => {
                let method = get_arg(&sub_m, "method", None);
                let payload = get_arg(&sub_m, "payload", None);
                get_vade(&sub_m)?.vc_zkp_create_credential_proposal(&method, "", &payload)
                    .await?
            }
            ("request_credential", Some(sub_m)) => {
                let method = get_arg(&sub_m, "method", None);
                let payload = get_arg(&sub_m, "payload", None);
                get_vade(&sub_m)?.vc_zkp_request_credential(&method, "", &payload)
                    .await?
            }
            ("request_proof", Some(sub_m)) => {
                let method = get_arg(&sub_m, "method", None);
                let payload = get_arg(&sub_m, "payload", None);
                get_vade(&sub_m)?.vc_zkp_request_proof(&method, "", &payload).await?
            }
            ("revoke_credential", Some(sub_m)) => {
                let method = get_arg(&sub_m, "method", None);
                let options = get_arg(&sub_m, "options", None);
                let payload = get_arg(&sub_m, "payload", None);
                get_vade(&sub_m)?.vc_zkp_revoke_credential(&method, &options, &payload)
                    .await?
            }
            ("verify_proof", Some(sub_m)) => {
                let method = get_arg(&sub_m, "method", None);
                let payload = get_arg(&sub_m, "payload", None);
                get_vade(&sub_m)?.vc_zkp_verify_proof(&method, "", &payload).await?
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

fn get_arg<'a>(matches: &'a ArgMatches, arg_name: &'a str, fallback: Option<&'a str>) -> &'a str {
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

fn get_arg_arg(arg_name: &str) -> Result<Arg, Box<dyn std::error::Error>> {
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

fn get_args() -> Result<ArgMatches<'static>, Box<dyn std::error::Error>> {
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
                        .arg(get_arg_arg("method")?)
                        .arg(get_arg_arg("options")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("resolve")
                        .about("Fetch data about a DID, which returns this DID's DID document.")
                        .arg(get_arg_arg("did")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("update")
                        .about(r###"Updates data related to a DID. Two updates are supported depending on the value of `options.operation`.
            - whitelistIdentity: whitelists identity `did` on substrate, this is required to be able to perform transactions this this identity
            - setDidDocument: sets the DID document for `did`"###)
                        .arg(get_arg_arg("did")?)
                        .arg(get_arg_arg("options")?)
                        .arg(get_arg_arg("payload")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
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
                    SubCommand::with_name("create_credential_definition")
                        .about("Creates a new credential definition and stores the public part on-chain. The private part (key) needs to be stored in a safe way and must not be shared. A credential definition holds cryptographic material needed to verify proofs. Every definition is bound to one credential schema. Note that `options.identity` needs to be whitelisted for this function.")
                        .arg(get_arg_arg("method")?)
                        .arg(get_arg_arg("options")?)
                        .arg(get_arg_arg("payload")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("create_credential_schema")
                        .about("Creates a new zero-knowledge proof credential schema. Note that `options.identity` needs to be whitelisted for this function.")
                        .arg(get_arg_arg("method")?)
                        .arg(get_arg_arg("options")?)
                        .arg(get_arg_arg("payload")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("create_revocation_registry_definition")
                        .about("Creates a new revocation registry definition and stores it on-chain. The definition consists of a public and a private part. The public part holds the cryptographic material needed to create non-revocation proofs. The private part needs to reside with the registry owner and is used to revoke credentials. Note that `options.identity` needs to be whitelisted for this function.")
                        .arg(get_arg_arg("method")?)
                        .arg(get_arg_arg("options")?)
                        .arg(get_arg_arg("payload")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("issue_credential")
                        .about("Issues a new credential. This requires an issued schema, credential definition, an active revocation registry and a credential request message.")
                        .arg(get_arg_arg("method")?)
                        .arg(get_arg_arg("payload")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("create_credential_offer")
                        .about("Creates a `CredentialOffer` message. A `CredentialOffer` is sent by an issuer and is the response to a `CredentialProposal`. The `CredentialOffer` specifies which schema and definition the issuer is capable and willing to use for credential issuance.")
                        .arg(get_arg_arg("method")?)
                        .arg(get_arg_arg("payload")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("present_proof")
                        .about("Presents a proof for one or more credentials. A proof presentation is the response to a proof request. The proof needs to incorporate all required fields from all required schemas requested in the proof request.")
                        .arg(get_arg_arg("method")?)
                        .arg(get_arg_arg("payload")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("create_credential_proposal")
                        .about("Creates a new zero-knowledge proof credential proposal. This message is the first in the credential issuance flow and is sent by the potential credential holder to the credential issuer.")
                        .arg(get_arg_arg("method")?)
                        .arg(get_arg_arg("payload")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("request_credential")
                        .about("Requests a credential. This message is the response to a credential offering and is sent by the potential credential holder. It incorporates the target schema, credential definition offered by the issuer, and the encoded values the holder wants to get signed. The credential is not stored on-chain and needs to be kept private.")
                        .arg(get_arg_arg("method")?)
                        .arg(get_arg_arg("payload")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("request_proof")
                        .about("Requests a zero-knowledge proof for one or more credentials issued under one or more specific schemas and is sent by a verifier to a prover. The proof request consists of the fields the verifier wants to be revealed per schema.")
                        .arg(get_arg_arg("method")?)
                        .arg(get_arg_arg("payload")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("revoke_credential")
                        .about("Revokes a credential. After revocation the published revocation registry needs to be updated with information returned by this function. To revoke a credential, tbe revoker must be in possession of the private key associated with the credential's revocation registry. After revocation, the published revocation registry must be updated. Only then is the credential truly revoked. Note that `options.identity` needs to be whitelisted for this function.")
                        .arg(get_arg_arg("method")?)
                        .arg(get_arg_arg("options")?)
                        .arg(get_arg_arg("payload")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
                )
                .subcommand(
                    SubCommand::with_name("verify_proof")
                        .about("Verifies a one or multiple proofs sent in a proof presentation.")
                        .arg(get_arg_arg("method")?)
                        .arg(get_arg_arg("payload")?)
                        .arg(get_arg_arg("target")?)
                        .arg(get_arg_arg("signer")?),
                )
        )
        .get_matches())
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

fn get_vade(matches: &ArgMatches<'static>) -> Result<Vade, Box<dyn std::error::Error>> {
    let target = get_arg(&matches, "target", Some("13.69.59.185"));
    let signer = get_arg(&matches, "signer", Some("local"));

    let mut vade = Vade::new();

    let signer_box: Box<dyn Signer> = get_signer(signer);

    vade.register_plugin(Box::from(SubstrateDidResolverEvan::new(ResolverConfig {
        signer: signer_box,
        target: target.to_string(),
    })));

    vade.register_plugin(Box::from(get_vade_evan(target, signer)?));

    Ok(vade)
}

fn get_vade_evan(target: &str, signer: &str) -> Result<VadeEvan, Box<dyn std::error::Error>> {
    let mut internal_vade = Vade::new();
    let signer_box: Box<dyn Signer> = get_signer(signer);
    internal_vade.register_plugin(Box::from(SubstrateDidResolverEvan::new(ResolverConfig {
        signer: signer_box,
        target: target.to_string(),
    })));
    let signer: Box<dyn Signer> = get_signer(signer);

    Ok(VadeEvan::new(internal_vade, signer))
}
