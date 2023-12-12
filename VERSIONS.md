# vade-evan

## Next Version

### Features

- add support to skip proof generation for revocation lists and when updating them (happens during revocation)
  - updated functions:
    - `vc_zkp_create_revocation_registry_definition`
    - `vc_zkp_revoke_credential`
  - these properties in payload are now optional:
    - `issuer_public_key_did`
    - `issuer_proving_key`
- add `helper_convert_credential_to_nquads` helper function
- add optional param `credential_values` to `helper_create_credential_offer` helper function
- update `helper_verify_presentation` for optional `signer_address`
- update `vade-didcomm` dependency for `create_pairwise_did` custom function

### Fixes

- fix revealed properties in `CredentialSubject`'s data in `create_presentation` helper
- remove unsued `credential_values` param from `helper_create_credential_request`
- update `vade-didcomm` dependency for `comment` fix in `did-exchange`
- update didcomm dependency for pthid in `get_did_exchange_message`

### Deprecation

- helper calls now have a different setup for `revoke_credential`
  - CLI calls for `helper revoke_credential`
    - drop mandatory argument `private_key`
    - get two new optional arguments `issuer_public_key_did` and `issuer_proving_key`
  - C calls have the arguments for `helper_revoke_credential` updated
    - positional 3rd argument (`private_key`) is moved to position 4 (`issuer_proving_key`)
    - new 3rd argument is now the verification method of the revocation list credential proof (`issuer_public_key_did`)
    - arguments now have the following order:
      - `credential: &str,`
      - `update_key_jwk: &str,`
      - `issuer_public_key_did: Option<&str>,`
      - `issuer_proving_key: Option<&str>,`
  - WASM calls now have the payload for `helper_revoke_credential` updated:
    - drop mandatory property `private_key`
    - get two new optional properties `issuer_public_key_did` and `issuer_proving_key`
- with proofs for revocation lists now being optional, the following updates to the exported types have been made:
  - `RevocationListCredential::proof` is now optional
  - `UnproofedRevocationListCredential` has been removed as proof of aforementioned struct can be set to `None`
- struct `AuthenticationOptions` and its usage has been removed as `identity` and `private_key` (in options) were not used anymore
- TypeScript typings updates
  - `UnproofedRevocationListCredential` has been marked as deprecated and will be removed in the future
  - `AuthenticationOptions` has been marked as deprecated and will be removed in the future
- remove payload parameter from `create_new_keys` custom function

## Release candidates

## 0.6.0-rc.6

### Fixes

- fix timestamp generation for `vade-didcomm` in `wasm` build

## 0.6.0-rc.5

### Features

- add support for `vc_zkp_propose_proof` function in `vade-evan-bbs` plugin
- add checks to ensure inputs that are supposed to be DIDs are really DIDs

## v0.5.0

### Features

- migrate `Vade` instance creation and plugin bundling to new `VadeEvan` API layer
- migration C-lib, CLI and WASM wrapper to use `VadeEvan` instead of `Vade`
- add `get_version_info` helper function
- add `create_credential_request` helper function
- add `create_credential_offer` helper function
- add `helper_verify_credential` helper function
- add `helper_did_create` and `helper_did_update` functions
- add `helper_revoke_credential` function
- pass sdk feature to vade-sidetree plugin
- update release ci to build and upload artifacts for android, ios, wasm, linux, macos and windows targets
- add `helper_create_self_issued_credential` helper function
- add `helper_create_proof_request`
- add optional params `update_key` and `recovery_key` to `did_create`
- add `helper_create_presentation`
- adjust `credential_status` property in `BbsCredential` to be optional
- refactor features to use target specific(c-lib, c-sdk, wasm, cli, java) builds
- adjust functions to remove `credential_subject.id` from `BbsCredential` and other types
- add `helper_verify_presentation`
- add support for `required_reveal_statements` in `vade-evan-bbs`
- adjust `helper_create_self_issued_credential` to create credentials without proof.
- add helper function `helper_create_self_issued_presentation` function
- update `vade-evan-bbs` dependency for revocation fix
- update `vade-evan-bbs` dependency optional proof in `ProofPresentation`

### Fixes

- add `payload` argument to did_create in CLI
- align key format for master secrets and public keys (no extra double quotes)
- fix optional params for did_create
- fix wasm release and `target-c-sdk` build options
- update dependencies for critical vulnerabilities
- fix revocation credential size increase with every revocation
- fix cli output for commands

### Deprecation

## v0.4.1

### Features

- migrate `Vade` instance creation and plugin bundling to new `VadeEvan` API layer
- migration C-lib, CLI and WASM wrapper to use `VadeEvan` instead of `Vade`
- add `get_version_info` helper function
- update vade-sidetree

## v0.4.0

### Features

- add sdk feature for in3 integration and request_list usage to resolve http requests
- create javascript wrapper for vade-evan
- setup pipeline for different targets
- use signing logic from `vade-signer` instead of `vade-evan-substrate`

## v0.3.0

### Features

- bump dependency versions

## v0.2.0

### Features

- add helper script for updating git based dependencies
- add create_keys subcommand to didcomm in cli
- add java jni wrapper code
- add query_didcomm_message subcommand to didcomm command in cli
- disable vade-evan-cl as dependency

## Version 0.1.2

### Fixes

- fix Linux and WASM build
- increase version for vade-didcomm vade-sidetree and added vade-jwt-vc features

## Version 0.1.1

### Fixes

- add git urls as dependencies

## Version 0.1.0

### Features

- add support for `didcomm_send`, `didcomm_receive`, `vc_zkp_finish_credential`
- add WASM complied project with sample javascript library
- made changes to pass external signer to vade-jwt-vc plugin

### Deprecations

- split off substrate logic from original `vade-evan` project into separate projects
  - did related components and signing went to `vade-evan-substrate`
  - cl vc related components went to `vade-evan-cl`

## Version 0.0.8

### Fixes

- fix links in documentation
- remove path from default `vade` and `ursa` dependencies

## Version 0.0.7

### Fixes

- fix badges in readme

## Version 0.0.6

- initial version after project renaming