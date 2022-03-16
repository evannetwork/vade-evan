# vade-evan

## Next Version

### Features

### Fixes

### Deprecation

## v0.2.0

### Features

- add helper script for updating git based dependencies
- add create_keys subcommand to didcomm in cli
- add java jni wrapper code
- add query_didcomm_message subcommand to didcomm command in cli

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
