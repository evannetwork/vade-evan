# vade-evan

## Next Version

### Features

- migrate `Vade` instance creation and plugin bundling to new `VadeEvan` API layer
- migration C-lib, CLI and WASM wrapper to use `VadeEvan` instead of `Vade`
- add `get_version_info` helper function
- add `get_credential_offer` helper function

### Fixes

### Deprecation

- refactor feature names and combinations

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
