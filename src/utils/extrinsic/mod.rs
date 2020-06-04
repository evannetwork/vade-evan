pub extern crate parity_scale_codec;
pub mod xt_primitives;
pub mod node_metadata;
pub mod frame_metadata;
pub mod rpc;
pub mod rpc_messages;
pub mod events;

/// Generates an Unchecked extrinsic for a given module and call passed as a &str.
/// # Arguments
///
/// * 'api' - This instance of API. If the *signer* field is not set, an unsigned extrinsic will be generated.
/// * 'module' - Module name as &str for which the call is composed.
/// * 'call' - Call name as &str
/// * 'args' - Optional sequence of arguments of the call. They are not checked against the metadata.
/// As of now the user needs to check himself that the correct arguments are supplied.

#[macro_export]
macro_rules! compose_extrinsic {
	($metadata: expr,
	$module: expr,
	$call: expr
	$(, $args: expr) *) => {
		{
            use $crate::log::info;
            use $crate::utils::extrinsic::xt_primitives::*;

            info!("Composing generic extrinsic for module {:?} and call {:?}", $module, $call);
            let call = $crate::compose_call!($metadata.clone(), $module, $call $(, ($args)) *);

            UncheckedExtrinsicV4 {
                function: call.clone(),
            }
		}
    };
}

/// Generates the extrinsic's call field for a given module and call passed as &str
/// # Arguments
///
/// * 'node_metadata' - This crate's parsed node metadata as field of the API.
/// * 'module' - Module name as &str for which the call is composed.
/// * 'call' - Call name as &str
/// * 'args' - Optional sequence of arguments of the call. They are not checked against the metadata.
/// As of now the user needs to check himself that the correct arguments are supplied.
#[macro_export]
macro_rules! compose_call {
($node_metadata: expr, $module: expr, $call_name: expr $(, $args: expr) *) => {
        {
            let module = $node_metadata.module_with_calls($module).unwrap().to_owned();

            let call_index = module.calls.get($call_name).unwrap();

            ([module.index, *call_index as u8] $(, ($args)) *)
        }
    };
}