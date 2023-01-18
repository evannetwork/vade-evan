use std::error::Error;
#[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
use std::os::raw::c_void;
use vade::Vade;
#[cfg(feature = "plugin-didcomm")]
use vade_didcomm::VadeDidComm;
#[cfg(feature = "plugin-vc-zkp-bbs")]
use vade_evan_bbs::VadeEvanBbs;
#[cfg(feature = "plugin-did-substrate")]
use vade_evan_substrate::{ResolverConfig, VadeEvanSubstrate};
#[cfg(feature = "plugin-jwt-vc")]
use vade_jwt_vc::VadeJwtVC;
#[cfg(feature = "plugin-did-sidetree")]
use vade_sidetree::VadeSidetree;
#[cfg(feature = "plugin-vade-signer")]
use vade_signer::{LocalSigner, RemoteSigner, Signer};
#[cfg(feature = "plugin-did-universal-resolver")]
use vade_universal_resolver::VadeUniversalResolver;

#[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
use crate::in3_request_list::ResolveHttpRequest;

fn get_signer(signer: &str) -> Box<dyn Signer> {
    if signer.starts_with("remote") {
        Box::new(RemoteSigner::new(
            signer.trim_start_matches("remote|").to_string(),
        ))
    } else if signer.starts_with("local") {
        Box::new(LocalSigner::new())
    } else {
        panic!("invalid signer config: {}", &signer)
    }
}

// variables might be unused depending on feature combination
#[allow(unused_variables)]
pub fn get_vade(
    target: &str,
    signer: &str,
    #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))] request_id: *const c_void,
    #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
    _request_function_callback: ResolveHttpRequest,
) -> Result<Vade, Box<dyn Error>> {
    let mut vade = Vade::new();

    #[cfg(feature = "plugin-did-substrate")]
    vade.register_plugin(Box::from(get_vade_evan_substrate(
        target,
        signer,
        #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
        request_id,
    )?));
    #[cfg(feature = "plugin-did-universal-resolver")]
    vade.register_plugin(Box::from(get_vade_universal_resolver(
        #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
        request_id,
        #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
        request_function_callback,
    )?));
    #[cfg(feature = "plugin-did-sidetree")]
    vade.register_plugin(Box::from(get_vade_sidetree(
        #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
        request_id,
    )?));
    #[cfg(feature = "plugin-vc-zkp-bbs")]
    vade.register_plugin(Box::from(get_vade_evan_bbs(
        signer,
        #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
        request_id,
    )?));

    #[cfg(feature = "plugin-jwt-vc")]
    vade.register_plugin(Box::from(get_vade_jwt_vc(
        signer,
        #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
        request_id,
    )?));

    #[cfg(feature = "plugin-didcomm")]
    vade.register_plugin(Box::from(VadeDidComm::new()?));

    Ok(vade)
}

#[cfg(feature = "plugin-vc-zkp-bbs")]
fn get_vade_evan_bbs(
    signer: &str,
    #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))] _request_id: *const c_void,
) -> Result<VadeEvanBbs, Box<dyn Error>> {
    let signer: Box<dyn Signer> = get_signer(signer);
    Ok(VadeEvanBbs::new(signer))
}

#[cfg(feature = "plugin-jwt-vc")]
fn get_vade_jwt_vc(
    signer: &str,
    #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))] _request_id: *const c_void,
) -> Result<VadeJwtVC, Box<dyn Error>> {
    Ok(VadeJwtVC::new(get_signer(signer)))
}

#[cfg(feature = "plugin-did-substrate")]
fn get_vade_evan_substrate(
    target: &str,
    signer: &str,
    #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))] _request_id: *const c_void,
) -> Result<VadeEvanSubstrate, Box<dyn Error>> {
    Ok(VadeEvanSubstrate::new(ResolverConfig {
        signer: get_signer(signer),
        target: target.to_string(),
    }))
}

#[cfg(feature = "plugin-did-universal-resolver")]
fn get_vade_universal_resolver(
    #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))] request_id: *const c_void,
    #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
    request_function_callback: ResolveHttpRequest,
) -> Result<VadeUniversalResolver, Box<dyn Error>> {
    Ok(VadeUniversalResolver::new(
        std::env::var("RESOLVER_URL").ok(),
        #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
        request_id,
        #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
        request_function_callback,
    ))
}

#[cfg(feature = "plugin-did-sidetree")]
fn get_vade_sidetree(
    #[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))] _request_id: *const c_void,
) -> Result<VadeSidetree, Box<dyn Error>> {
    Ok(VadeSidetree::new(std::env::var("SIDETREE_API_URL").ok()))
}
