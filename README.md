# Vade Evan

[![Apache-2 licensed](https://img.shields.io/crates/l/vade-evan.svg)](./LICENSE.txt)

## About

This crate allows you to use to work with DIDs and zero knowledge proof VCs.
It offers a command line interface and support to build package for C, Java, WASM, and exports a `VadeEvan` API to use the same functionalities in other Rust projects.

## Compiling vade-evan

### "Regular" build

No surprise here:

```sh
cargo build --release
```

### Default Features

By default features `did-sidetree`, `did-substrate`, `didcomm`, `jwt-vc`, `vc-zkp-bbs`, `cli` are used, so a default feature bundle is used and compiled to a command line interface, so basically using the default feature setup (like above) builds the same as:

```sh
cargo build --release --no-default-features --features did-sidetree, did-substrate, didcomm, jwt-vc, vc-zkp-bbs, cli
```

When building `vade-evan`, you usually use `target-` feature, which means that you want to include a certain set of features and want to make it available for a certain target/platform.

### Targets

Targets define for which platform you want to build a vade package. Also more building for more than one target is not supported. Currently these targets are available:

- `target-c-sdk` - build for usage in IN3 SDK with request list
```sh
cargo build --release --no-default-features --features target-c-sdk
```
- `target-c-lib` - build for usage in C
```sh
cargo build --release --no-default-features --features target-c-lib
```
- `target-cli` - build command line interface --> `./target/release/vade_evan_cli`
```sh
cargo build --release --no-default-features --features target-cli
```
- `target-java-lib` - build for usage in Java
```sh
cargo build --release --no-default-features --features target-java-lib
```
- `target-wasm` - in combination with `wasm-pack`, build for usage in WASM (see below)
```sh
wasm-pack build --release --target nodejs -- --no-default-features --features target-wasm
```

One (and only one) target must be provided when building without default features.

## About the builds

### C builds with sdk feature

Features can be adjusted to support integration with IN3 SDK by enabling `target-c-sdk` feature. `target-c-sdk` feature enables `HTTP` request/response managed via IN3 SDK.

```sh
cargo build --release --no-default-features --features target-c-sdk
```
#### Limitations of target-c-sdk feature

`target-c-sdk` feature can't be used with `target-wasm`, `target-java-lib` and `target-cli` as in3 sdk specific request list pointers are integrated only with `target-c-sdk` as parameters in c-lib interface. If someone has specific need to use sdk request list pointers with targets  other than `target-c-sdk`, it will have to be done separately by editing wasm or java interfaces.

### WASM

#### WASM pack

To compile `vade-evan` for wasm, use wasm-pack, you can specify whether to build a browser or a nodejs environment with wasm-pack's `--target` argument. Also use the `target-wasm` feature to tell the compile how to configure `vade-evan` for the vade build.

nodejs:

```sh
wasm-pack build --release --target nodejs -- --no-default-features --features target-wasm
```

browser:

```sh
wasm-pack build --release --target web -- --no-default-features --features target-wasm
```

#### Wrapper for WASM pack

A project that wraps calls against the WASM file has been added and placed at `builds/wasm`.

To build it, you need to have to build `vade-evan` as described above, navigate to `builds/wasm` and call

```sh
yarn && yarn build
```

If you want to try it out, navigate to `builds/wasm/example` and run

```sh
yarn && node index.js
```

This example will generate a new DID, assign a document to it and update it afterwards.

## Features

### Feature name schema

Features in this project follow a naming schema that looks as following:

- `target-` features decide which build target (CLI, WASM, SDK, etc.) to build for

`target-` features are intended to be used for build/run commands. Others should only be used from within `Cargo.toml` to allow including functionalities in the source files.

### Feature overview

| feature              | default | contents                             |
|----------------------|:-------:|--------------------------------------|
| target-c-sdk         |         | build for usage in SDK request_list  |
| target-c-lib         |         | build for usage in C                 |
| target-cli           |    x    | build command line interface         |
| target-java-lib      |         | build for usage in Java              |
| target-wasm          |         | build for usage in WASM              |
| did-sidetree         |    x    | add support for using sidetree DIDs  |
| did-substrate        |    x    | add support for using substrate DIDs |
| didcomm              |    x    | add DIDComm support                  |
| jwt-vc               |    x    | add support for JWT VCs              |
| vc-zkp-bbs           |    x    | add support for BBS VCs              |

## Dependencies

At the moment all vade related dependencies (vade itself and its plugins) are supposed to be pulled from the latest commit of the `develop` branch. As the dependency handling stores the hash of this commit in the lock file, updates on `develop` branch are not used by default.

If those updates should be pulled, the entry in the `Cargo.lock` file has to be deleted and `cargo build` has to be run again to update these hashes. If wanting to update specific dependencies, those can be deleted from the `Cargo.lock` by hand. If wanting to update all of the vade related dependencies, a script (`scripts/remove-vade-dependencies-from-lockfile.sh`) can be used. Note that this script relies on [dasel] so this must be installed locally, e.g. with homebrew.

[dasel]: https://github.com/TomWright/dasel
[`Vade`]: https://docs.rs/vade_evan/*/vade/struct.Vade.html
