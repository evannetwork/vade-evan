use std::error::Error;
use vade::Vade;
#[cfg(feature = "didcomm")]
use vade_didcomm::VadeDidComm;
#[cfg(feature = "vc-zkp")]
use vade_evan_bbs::VadeEvanBbs;
#[cfg(feature = "vc-zkp")]
use vade_evan_cl::VadeEvanCl;
#[cfg(feature = "did")]
use vade_evan_substrate::{
    signing::{LocalSigner, RemoteSigner, Signer},
    ResolverConfig,
    VadeEvanSubstrate,
};
#[cfg(feature = "did")]
use vade_universal_resolver::VadeUniversalResolver;
#[cfg(feature = "did")]
use vade_sidetree::VadeSidetree;

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

    #[cfg(feature = "did")]
    vade.register_plugin(Box::from(get_resolver(target, signer)?));
    #[cfg(feature = "did")]
    vade.register_plugin(Box::from(get_universal_resolver()?));
    #[cfg(feature = "did")]
    vade.register_plugin(Box::from(get_vade_sidetree()?));
    #[cfg(feature = "vc-zkp")]
    vade.register_plugin(Box::from(get_vade_evan_cl(target, signer)?));
    #[cfg(feature = "vc-zkp")]
    vade.register_plugin(Box::from(get_vade_evan_bbs(target, signer)?));
    #[cfg(feature = "didcomm")]
    vade.register_plugin(Box::from(VadeDidComm::new()?));

    Ok(vade)
}

#[cfg(feature = "vc-zkp")]
fn get_vade_evan_cl(target: &str, signer: &str) -> Result<VadeEvanCl, Box<dyn Error>> {
    let mut internal_vade = Vade::new();
    #[cfg(feature = "did")]
    internal_vade.register_plugin(Box::from(get_resolver(target, signer)?));
    #[cfg(feature = "did")]
    internal_vade.register_plugin(Box::from(get_vade_sidetree()?));
    #[cfg(feature = "did")]
    internal_vade.register_plugin(Box::from(get_universal_resolver()?));

    let signer: Box<dyn Signer> = get_signer(signer);
    Ok(VadeEvanCl::new(internal_vade, signer))
}

#[cfg(feature = "vc-zkp")]
fn get_vade_evan_bbs(target: &str, signer: &str) -> Result<VadeEvanBbs, Box<dyn Error>> {
    let mut internal_vade = Vade::new();
    #[cfg(feature = "did")]
    internal_vade.register_plugin(Box::from(get_resolver(target, signer)?));
    #[cfg(feature = "did")]
    internal_vade.register_plugin(Box::from(get_vade_sidetree()?));
    #[cfg(feature = "did")]
    internal_vade.register_plugin(Box::from(get_universal_resolver()?));

    let signer: Box<dyn Signer> = get_signer(signer);
    Ok(VadeEvanBbs::new(internal_vade, signer))
}

#[cfg(feature = "did")]
fn get_resolver(target: &str, signer: &str) -> Result<VadeEvanSubstrate, Box<dyn Error>> {
    Ok(VadeEvanSubstrate::new(ResolverConfig {
        signer: get_signer(signer),
        target: target.to_string(),
    }))
}

#[cfg(feature = "did")]
fn get_universal_resolver() -> Result<VadeUniversalResolver, Box<dyn Error>> {
    Ok(VadeUniversalResolver::new(
        std::env::var("RESOLVER_URL").ok(),
    ))
}

#[cfg(feature = "did")]
fn get_vade_sidetree() -> Result<VadeSidetree, Box<dyn Error>> {
    Ok(VadeSidetree::new(
        std::env::var("SIDETREE_API_URL").ok(),
    ))
}
