# Vade Evan

[![crates.io](https://img.shields.io/crates/v/vade.svg)](https://crates.io/crates/vade-evan)
[![Documentation](https://docs.rs/vade/badge.svg)](https://docs.rs/vade:q)
[![Apache-2 licensed](https://img.shields.io/crates/l/vade.svg)](./LICENSE.txt)

## About

This crate allows you to use to work with DIDs and zero knowledge proof VCs on Trust and Trace.
For this purpose two [`VadePlugin`] implementations are exported: [`VadeEvan`] and [`SubstrateDidResolverEvan`].

## VadeEvan

Responsible for working with zero knowledge proof VCs on Trust and Trace.

Implements the following [`VadePlugin`] functions:

- [`vc_zkp_create_credential_schema`]
- [`vc_zkp_create_credential_definition`]
- [`vc_zkp_create_credential_proposal`]
- [`vc_zkp_create_credential_offer`]
- [`vc_zkp_request_credential`]
- [`vc_zkp_create_revocation_registry_definition`]
- [`vc_zkp_update_revocation_registry`]
- [`vc_zkp_issue_credential`]
- [`vc_zkp_revoke_credential`]
- [`vc_zkp_request_proof`]
- [`vc_zkp_present_proof`]
- [`vc_zkp_verify_proof`]

## SubstrateDidResolverEvan

Supports creating, updating and getting DIDs and DID documents on substrate, therefore supports:

- [`did_create`]
- [`did_resolve`]
- [`did_update`]

[`did_create`]: https://docs.rs/vade_evan/*/vade_evan/resolver/struct.SubstrateDidResolverEvan.html#method.did_create
[`did_resolve`]: https://docs.rs/vade_evan/*/vade_evan/resolver/struct.SubstrateDidResolverEvan.html#method.did_resolve
[`did_update`]: https://docs.rs/vade_evan/*/vade_evan/resolver/struct.SubstrateDidResolverEvan.html#method.did_update
[`SubstrateDidResolverEvan`]: https://docs.rs/vade_evan/*/vade_evan/resolver/struct.SubstrateDidResolverEvan.html
[`Vade`]: https://docs.rs/vade_evan/*/vade/struct.Vade.html
[`VadePlugin`]: https://docs.rs/vade_evan/*/vade/trait.VadePlugin.html
[`VadeEvan`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html
[`vc_zkp_create_credential_definition`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_create_credential_definition
[`vc_zkp_create_credential_offer`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_create_credential_offer
[`vc_zkp_create_credential_proposal`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_create_credential_proposal
[`vc_zkp_create_credential_schema`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_create_credential_schema
[`vc_zkp_create_revocation_registry_definition`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_create_revocation_registry_definition
[`vc_zkp_issue_credential`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_issue_credential
[`vc_zkp_present_proof`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_present_proof
[`vc_zkp_request_credential`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_request_credential
[`vc_zkp_request_proof`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_request_proof
[`vc_zkp_revoke_credential`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_revoke_credential
[`vc_zkp_update_revocation_registry`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_update_revocation_registry
[`vc_zkp_verify_proof`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_verify_proof
