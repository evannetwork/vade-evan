extern crate clap;
use clap::{App, Arg, ArgMatches};
use ursa::cl::prover::Prover;
use vade::Vade;
use vade_evan::{
    resolver::{ResolverConfig, SubstrateDidResolverEvan},
    signing::{LocalSigner, RemoteSigner, Signer},
    VadeEvan,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = get_args();

    let mut vade = get_vade(
        get_arg(&matches, "target", Some("13.69.59.185")),
        get_arg(&matches, "signer", Some("local")),
    )
    .unwrap();

    let command = get_arg(&matches, "command", Some(""));
    let mut did = "";
    let mut method = "";

    if command.starts_with("did_") {
        did = get_arg(&matches, "did", None);
    } else if command.starts_with("vc_zkp_") {
        method = get_arg(&matches, "method", None);
    }

    let options = get_arg(&matches, "options", Some(""));
    let payload = get_arg(&matches, "payload", Some(""));

    let results = match command {
        "create_master_secret" => vec![Some(
            serde_json::to_string(&Prover::new_master_secret().unwrap()).unwrap(),
        )],
        "did_create" => vade.did_create(&did, &options, &payload).await.unwrap(),
        "did_resolve" => vade.did_resolve(&did).await.unwrap(),
        "did_update" => vade.did_update(&did, &options, &payload).await?,
        "vc_zkp_create_credential_definition" => vade
            .vc_zkp_create_credential_definition(&method, &options, &payload)
            .await
            .unwrap(),
        "vc_zkp_create_credential_schema" => vade
            .vc_zkp_create_credential_schema(&method, &options, &payload)
            .await
            .unwrap(),
        "vc_zkp_create_revocation_registry_definition" => vade
            .vc_zkp_create_revocation_registry_definition(&method, &options, &payload)
            .await
            .unwrap(),
        "vc_zkp_issue_credential" => vade
            .vc_zkp_issue_credential(&method, &options, &payload)
            .await
            .unwrap(),
        "vc_zkp_create_credential_offer" => vade
            .vc_zkp_create_credential_offer(&method, &options, &payload)
            .await
            .unwrap(),
        "vc_zkp_present_proof" => vade
            .vc_zkp_present_proof(&method, &options, &payload)
            .await
            .unwrap(),
        "vc_zkp_create_credential_proposal" => vade
            .vc_zkp_create_credential_proposal(&method, &options, &payload)
            .await
            .unwrap(),
        "vc_zkp_request_credential" => vade
            .vc_zkp_request_credential(&method, &options, &payload)
            .await
            .unwrap(),
        "vc_zkp_request_proof" => vade
            .vc_zkp_request_proof(&method, &options, &payload)
            .await
            .unwrap(),
        "vc_zkp_revoke_credential" => vade
            .vc_zkp_revoke_credential(&method, &options, &payload)
            .await
            .unwrap(),
        "vc_zkp_verify_proof" => vade
            .vc_zkp_verify_proof(&method, &options, &payload)
            .await
            .unwrap(),
        _ => panic!("unsupported command: {}", &command),
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

fn get_args() -> ArgMatches<'static> {
    App::new("vade_evan_bin")
        .version("0.0.6")
        .author("evan GmbH")
        .about("allows you to use to work with DIDs and zero knowledge proof VCs on Trust and Trace")
        .arg(
            Arg::with_name("command")
                .long("command")
                .short("c")
                .required(true)
                .value_name("command")
                .help("vade command, e.g. 'vc_zkp_issue_credential'")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("did")
                .long("did")
                .short("d")
                .value_name("did")
                .help("a DID to work on, e.g. 'did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906'")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("method")
                .long("method")
                .short("m")
                .value_name("method")
                .help("method to work on, e.g. 'did:evan'")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("options")
                .long("options")
                .short("o")
                .value_name("options")
                .help("options to send to vade call, serialized JSON, e.g. '{ \"identity\": \"...\", \"privateKey\": \"...\" }'")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("payload")
                .long("payload")
                .short("p")
                .value_name("payload")
                .help("options to send to vade call, serialized JSON, e.g. '{ \"foo\": \"bar\" }'")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("target")
                .long("target")
                .short("t")
                .value_name("target")
                .help("substrate to use for DID handling, e.g. '127.0.0.1'")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("signer")
                .long("signer")
                .short("s")
                .value_name("signer")
                .help("signer to use to sign messages with, e.g. 'local' or 'remote|http://somewhere'")
                .takes_value(true),
        )
        .get_matches()
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

fn get_vade(target: &str, signer: &str) -> Result<Vade, Box<dyn std::error::Error>> {
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
