use std::error::Error;
use vade::Vade;
#[cfg(feature = "didcomm")]
use vade_didcomm::VadeDidComm;
#[cfg(feature = "vc-zkp-bbs")]
use vade_evan_bbs::VadeEvanBbs;
#[cfg(feature = "vc-zkp-cl")]
use vade_evan_cl::VadeEvanCl;
#[cfg(feature = "did-substrate")]
use vade_evan_substrate::{
    signing::{LocalSigner, RemoteSigner, Signer},
    ResolverConfig,
    VadeEvanSubstrate,
};
#[cfg(feature = "vc-jwt")]
use vade_jwt_vc::VadeJwtVC;
#[cfg(feature = "did-sidetree")]
use vade_sidetree::VadeSidetree;
#[cfg(feature = "did-universal-resolver")]
use vade_universal_resolver::VadeUniversalResolver;

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

#[allow(dead_code)]
pub fn get_config_default(key: &str) -> Result<String, Box<dyn Error>> {
    Ok(match key {
        "signer" => "local",
        "target" => "substrate-dev.trust-trace.com",
        _ => return Err(Box::from(format!("invalid invalid config key '{}'", key))),
    }
    .to_string())
}

pub fn get_vade(target: &str, signer: &str) -> Result<Vade, Box<dyn Error>> {
    let mut vade = Vade::new();

    #[cfg(feature = "did-substrate")]
    vade.register_plugin(Box::from(get_vade_evan_substrate(target, signer)?));
    #[cfg(feature = "did-universal-resolver")]
    vade.register_plugin(Box::from(get_vade_universal_resolver()?));
    #[cfg(feature = "did-sidetree")]
    vade.register_plugin(Box::from(get_vade_sidetree()?));
    #[cfg(feature = "vc-zkp-cl")]
    vade.register_plugin(Box::from(get_vade_evan_cl(target, signer)?));
    #[cfg(feature = "vc-zkp-bbs")]
    vade.register_plugin(Box::from(get_vade_evan_bbs(target, signer)?));
    #[cfg(feature = "vc-jwt")]
    vade.register_plugin(Box::from(get_vade_jwt_vc()?));
    #[cfg(feature = "didcomm")]
    vade.register_plugin(Box::from(VadeDidComm::new()?));

    Ok(vade)
}

#[cfg(feature = "vc-zkp-cl")]
fn get_vade_evan_cl(target: &str, signer: &str) -> Result<VadeEvanCl, Box<dyn Error>> {
    let mut vade = Vade::new();

    #[cfg(feature = "did-substrate")]
    vade.register_plugin(Box::from(get_vade_evan_substrate(target, signer)?));
    #[cfg(feature = "did-universal-resolver")]
    vade.register_plugin(Box::from(get_vade_universal_resolver()?));
    #[cfg(feature = "did-sidetree")]
    vade.register_plugin(Box::from(get_vade_sidetree()?));

    let signer: Box<dyn Signer> = get_signer(signer);
    Ok(VadeEvanCl::new(vade, signer))
}

#[cfg(feature = "vc-zkp-bbs")]
fn get_vade_evan_bbs(target: &str, signer: &str) -> Result<VadeEvanBbs, Box<dyn Error>> {
    let mut vade = Vade::new();

    #[cfg(feature = "did-substrate")]
    vade.register_plugin(Box::from(get_vade_evan_substrate(target, signer)?));
    #[cfg(feature = "did-universal-resolver")]
    vade.register_plugin(Box::from(get_vade_universal_resolver()?));
    #[cfg(feature = "did-sidetree")]
    vade.register_plugin(Box::from(get_vade_sidetree()?));

    let signer: Box<dyn Signer> = get_signer(signer);
    Ok(VadeEvanBbs::new(signer))
}

#[cfg(feature = "vc-jwt")]
fn get_vade_jwt_vc() -> Result<VadeJwtVC, Box<dyn Error>> {
    Ok(VadeJwtVC::new())
}

#[cfg(feature = "did-substrate")]
fn get_vade_evan_substrate(
    target: &str,
    signer: &str,
) -> Result<VadeEvanSubstrate, Box<dyn Error>> {
    Ok(VadeEvanSubstrate::new(ResolverConfig {
        signer: get_signer(signer),
        target: target.to_string(),
    }))
}

#[cfg(feature = "did-universal-resolver")]
fn get_vade_universal_resolver() -> Result<VadeUniversalResolver, Box<dyn Error>> {
    Ok(VadeUniversalResolver::new(
        std::env::var("RESOLVER_URL").ok(),
    ))
}

#[cfg(feature = "did-sidetree")]
fn get_vade_sidetree() -> Result<VadeSidetree, Box<dyn Error>> {
    Ok(VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok()))
}
