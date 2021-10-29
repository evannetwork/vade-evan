# Vade Evan

[![Apache-2 licensed](https://img.shields.io/crates/l/vade-evan.svg)](./LICENSE.txt)

## About

This crate allows you to use to work with DIDs and zero knowledge proof VCs on Trust and Trace.
It offers a command line interface and a wasm package to work with a pre-configured [`Vade`] instance for Trust and Trace.

## Compiling vade-evan

### "Regular" build

No surprise here:

```sh
cargo build --release
```

### Default Features

By default features `cli`, `did`, `didcomm`, `portable`, and `vc-zkp` are used. So everything included and available for usage in command line interface.

Features can be omitted. So for example `vc-zkp` or `did` could be skipped.

### DID Features

By default the feature `did` enables did related operations => `did-resolve`, `did-create`, `did-update` using `vade-evan-substrate` and `did-resolve` using `vade-universal-resolver` plugins.

We also support did operations for sidetree based implementation which can be enabled if you are using non-default features, to enable it add the feature `did-sidetree` to the features set.

```sh
cargo build --release --no-default-features --features cli,did-sidetree,did-read,did-write,portable,vc-zkp
```

In a similar manner if you want to use either `vade-evan-substrate` or `vade-universal-resolver`, you have to add them to features set.

```sh
cargo build --release --no-default-features --features cli,did-substrate,did-read,did-write,portable,vc-zkp
```

```sh
cargo build --release --no-default-features --features cli,did-universal-resolver,did-read,portable,vc-zkp
```

Features can be adjusted for specific needs, if you want to restrict read (`did-resolve`) or write (`did-create` and `did-update`) operations for DIDs.

```sh
cargo build --release --no-default-features --features cli,did-sidetree,did-write,portable,vc-zkp
```

```sh
cargo build --release --no-default-features --features cli,did-sidetree,did-read,portable,vc-zkp
```

### Command Line Interface

If you are using non-default features, enable the cli just add the feature `cli` to the feature set:

```sh
cargo build --release --features cli
```

You can now use the `vade-evan` cli. Get started by having a look at the help shown after calling it with:

```sh
./target/release/vade_evan_cli
```

### WASM

#### WASM pack

To compile `vade-evan` for wasm, use wasm pack.

You can specify to use only `did` feature or to use `did` and `vc-zkp`. The following examples will use both features.

Also you have to specify whether to build a browser or a nodejs environment.

nodejs:

```sh
wasm-pack build --release --target nodejs -- --no-default-features --features did,vc-zkp,wasm
```

browser:

```sh
wasm-pack build --release --target web -- --no-default-features --features did,vc-zkp,wasm
```

#### Wrapper for WASM pack

A project that wraps calls against the WASM file has been added and placed at `builds/wasm`.

To build it, you need to have checked out next to your `vade-evan` project:

- `vade-evan-cl`
- `vade-evan-bbs`
- `vade-evan-didcomm`
- `vade-evan-substrate`

Then it can be build by navigating to `builds/wasm` and calling

```sh
yarn && yarn build
```

If you want to try it out, navigate to `builds/wasm/example` and run

```sh
yarn && node index.js
```

This example will generate a new DID, assign a document to it and update it afterwards.

### Features for building

| feature                | default | contents |
| ---------------------- |:-------:| -------- |
| cli                    |     x   | enables command line interface |
| c-lib                  |         | expose C interface for C applications to use vade |
| did                    |     x   | enables DID functionalities |
| did-read               |     x   | enables did_resolve method for DID related operations |
| did-write              |     x   | enables did_create and did_update methods for DID related operations |
| did-substrate          |     x   | enables DID functionalities (did_resolve, did_create, did_update ) using vade-evan-substrate plugin |
| did-universal-resolver |     x   | enables did_resolve method using vade-universal-resolver plugin |
| did-sidetree           |         | enables DID functionalities for Sidetree based implementation using vade-sidetree plugin |
| didcomm                |     x   | enables DIDComm message handling |
| vc-zkp                 |     x   | enables VC functionalities |
| portable               |     x   | build with optimizations to run natively, not compatible with `wasm` feature |
| wasm                   |         | build with optimizations to run as web assembly, not compatible with `portable` |

[`Vade`]: https://docs.rs/vade_evan/*/vade/struct.Vade.html
