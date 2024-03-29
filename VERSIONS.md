# vade-evan

## Next Version

### Features

- add support for `vc_zkp_propose_proof` function in `vade-evan-bbs` plugin
- add checks to ensure inputs that are supposed to be DIDs are really DIDs

### Fixes

- fix timestamp generation for `vade-didcomm` in `wasm` build
- update didcomm dependency for pthid in `get_did_exchange_message`
- update `vade-didcomm` dependency for `comment` fix in `did-exchange`

### Deprecation

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
- update `vade-evan-bbs` dependency for revocation fix

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
