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

By default features `bundle-default`, `target-cli` are used, so a default feature bundle is used and compiled to a command line interface, so basically using the default feature setup (like above) builds the same as:

```sh
cargo build --release --no-default-features --features bundle-default,target-cli
```

When building `vade-evan`, you usually combine a `bundle-` feature and a `target-` feature, which means that you want to include a certain set of features and want to make it available for a certain target/platform.

### Bundles

Bundles define which plugins you want to include in your `vade-evan` build, which usually has an impact on the available functions and utilized plugins to handle them.

Bundles are not mandatory as you can also create the same plugin setup by just defining the plugins. Bundle `bundle-default` for example includes `plugin-did-sidetree`, `plugin-did-substrate`, `plugin-didcomm`, `plugin-jwt-vc`, and `plugin-vc-zkp-bbs`. Those can be recombined if desired, e.g. if no DIDComm support is desired, `plugin-didcomm` can be omitted:

```sh
cargo build --release --no-default-features --features plugin-did-sidetree,plugin-did-substrate,plugin-jwt-vc,plugin-vc-zkp-bbs,target-cli
```

Note that `plugin-vc-zkp-bbs` relies on `plugin-did-sidetree` to persist data in some steps, so omitting it would impart some of the `plugin-vc-zkp-bbs` functionalities.

At the moment two bundles are offered by `vade-evan`: `bundle-default` and `bundle-sdk`.

### Targets

Targets define for which platform you want to build a vade package. Also more building for more than one target is not supported. Currently these targets are available:

- `target-c-lib` - build for usage in C
- `target-cli` - build command line interface --> `./target/release/vade_evan_cli`
- `target-java-lib` - build for usage in Java
- `target-wasm` - in combination with `wasm-pack`, build for usage in WASM (see below)

One (and only one) target must be provided when building without default features.

## About the builds

### C builds with sdk feature

Features can be adjusted to support integration with IN3 SDK by enabling `bundle-sdk` feature. `bundle-sdk` feature in combination with `target-c-lib` feature enables `HTTP` request/response managed via IN3 SDK.

```sh
cargo build --release --no-default-features --features bundle-sdk,target-c-lib
```
#### Limitations of bundle-sdk feature

bundle-sdk feature can't be used with `target-wasm`, `target-java-lib` and `target-cli` as in3 sdk specific request list pointers are integrated only with `target-c-lib` as parameters in c-lib interface. If someone has specific need to use sdk request list pointers with targets  other than `target-c-lib`, it will have to be done separately by editing wasm or java interfaces.

### WASM

#### WASM pack

To compile `vade-evan` for wasm, use wasm-pack, you can specify whether to build a browser or a nodejs environment with wasm-pack's `--target` argument. Also use the `target-wasm` feature to tell the compile how to configure `vade-evan` for the vade build.

nodejs:

```sh
wasm-pack build --release --target nodejs -- --no-default-features --features bundle-default,target-wasm
```

browser:

```sh
wasm-pack build --release --target web -- --no-default-features --features bundle-default,target-wasm
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

- `bundle-` features decide which (`VadePlugin`) plugins to include
- `target-` features decide which build target (CLI, WASM, etc.) to build for
- `plugin-` feature take care, that plugins and related dependencies are present
- `capability-` features control which functionalities a `plugin-` may offer

`bundle-`, `target-` and `plugin-` are intended to be used for build/run commands. `capability-` should only be used from within `Cargo.toml` to allow including functionalities in the source files.

### Feature overview

| feature              | default | contents                             |
|----------------------|:-------:|--------------------------------------|
| bundle-default       |    x    | include default plugins              |
| bundle-sdk           |         | include plugins for sdk              |
| target-c-lib         |         | build for usage in C                 |
| target-cli           |    x    | build command line interface         |
| target-java-lib      |         | build for usage in Java              |
| target-wasm          |         | build for usage in WASM              |
| plugin-did-sidetree  |    x    | add support for using sidetree DIDs  |
| plugin-did-substrate |    x    | add support for using substrate DIDs |
| plugin-didcomm       |    x    | add DIDComm support                  |
| plugin-jwt-vc        |    x    | add support for JWT VCs              |
| plugin-vc-zkp-bbs    |    x    | add support for BBS VCs              |

## Dependencies

At the moment all vade related dependencies (vade itself and its plugins) are supposed to be pulled from the latest commit of the `develop` branch. As the dependency handling stores the hash of this commit in the lock file, updates on `develop` branch are not used by default.

If those updates should be pulled, the entry in the `Cargo.lock` file has to be deleted and `cargo build` has to be run again to update these hashes. If wanting to update specific dependencies, those can be deleted from the `Cargo.lock` by hand. If wanting to update all of the vade related dependencies, a script (`scripts/remove-vade-dependencies-from-lockfile.sh`) can be used. Note that this script relies on [dasel] so this must be installed locally, e.g. with homebrew.

[dasel]: https://github.com/TomWright/dasel
[`Vade`]: https://docs.rs/vade_evan/*/vade/struct.Vade.html
