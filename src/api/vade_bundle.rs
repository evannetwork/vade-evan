use std::error::Error;
#[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
use std::os::raw::c_void;
use vade::Vade;
#[cfg(feature = "didcomm")]
use vade_didcomm::VadeDidComm;
#[cfg(feature = "vc-zkp-bbs")]
use vade_evan_bbs::VadeEvanBbs;
#[cfg(feature = "did-substrate")]
use vade_evan_substrate::{ResolverConfig, VadeEvanSubstrate};
#[cfg(feature = "jwt-vc")]
use vade_jwt_vc::VadeJwtVC;
#[cfg(feature = "did-sidetree")]
use vade_sidetree::VadeSidetree;
#[cfg(feature = "signer")]
use vade_signer::{LocalSigner, RemoteSigner, Signer};
#[cfg(feature = "did-universal-resolver")]
use vade_universal_resolver::VadeUniversalResolver;

#[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
use crate::in3_request_list::ResolveHttpRequest;

#[cfg(any(
    feature = "vc-zkp-bbs",
    feature = "jwt-vc",
    feature = "did-substrate"
))]
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
    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] request_id: *const c_void,
    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
    request_function_callback: ResolveHttpRequest,
) -> Result<Vade, Box<dyn Error>> {
    let mut vade = Vade::new();

    #[cfg(feature = "did-substrate")]
    vade.register_plugin(Box::from(get_vade_evan_substrate(
        target,
        signer,
        #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
        request_id,
    )?));
    #[cfg(feature = "did-universal-resolver")]
    vade.register_plugin(Box::from(get_vade_universal_resolver(
        #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
        request_id,
        #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
        request_function_callback,
    )?));
    #[cfg(feature = "did-sidetree")]
    vade.register_plugin(Box::from(get_vade_sidetree(
        #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
        request_id,
        #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
        request_function_callback,
    )?));
    #[cfg(feature = "vc-zkp-bbs")]
    vade.register_plugin(Box::from(get_vade_evan_bbs(
        signer,
        #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
        request_id,
    )?));

    #[cfg(feature = "jwt-vc")]
    vade.register_plugin(Box::from(get_vade_jwt_vc(
        signer,
        #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
        request_id,
    )?));

    #[cfg(feature = "didcomm")]
    vade.register_plugin(Box::from(VadeDidComm::new()?));

    Ok(vade)
}

#[cfg(feature = "vc-zkp-bbs")]
fn get_vade_evan_bbs(
    signer: &str,
    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] _request_id: *const c_void,
) -> Result<VadeEvanBbs, Box<dyn Error>> {
    let signer: Box<dyn Signer> = get_signer(signer);
    Ok(VadeEvanBbs::new(signer))
}

#[cfg(feature = "jwt-vc")]
fn get_vade_jwt_vc(
    signer: &str,
    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] _request_id: *const c_void,
) -> Result<VadeJwtVC, Box<dyn Error>> {
    Ok(VadeJwtVC::new(get_signer(signer)))
}

#[cfg(feature = "did-substrate")]
fn get_vade_evan_substrate(
    target: &str,
    signer: &str,
    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] _request_id: *const c_void,
) -> Result<VadeEvanSubstrate, Box<dyn Error>> {
    Ok(VadeEvanSubstrate::new(ResolverConfig {
        signer: get_signer(signer),
        target: target.to_string(),
    }))
}

#[cfg(feature = "did-universal-resolver")]
fn get_vade_universal_resolver(
    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] request_id: *const c_void,
    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
    request_function_callback: ResolveHttpRequest,
) -> Result<VadeUniversalResolver, Box<dyn Error>> {
    Ok(VadeUniversalResolver::new(
        std::env::var("RESOLVER_URL").ok(),
        #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
        request_id,
        #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
        request_function_callback,
    ))
}

#[cfg(feature = "did-sidetree")]
fn get_vade_sidetree(
    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] request_id: *const c_void,
    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
    request_function_callback: ResolveHttpRequest,
) -> Result<VadeSidetree, Box<dyn Error>> {
    Ok(VadeSidetree::new(
        #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
        request_id,
        #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
        request_function_callback,
        std::env::var("SIDETREE_API_URL").ok()
    ))
}
