# Sample C code to use vade-evan

## About

This sample code demonstrates how to call vade functions from C code


### How to build

Compile vade-evan with `c-lib` feature enabled, for integration with in3 sdk an addtional `sdk` feature should be enabled.

```sh
cargo build --release --no-default-features --features did-sidetree,did-write,didcomm,portable,vc-zkp,c-lib,sdk
```

Once vade-evan is compiled and lib is generated target folder, use following build command to generate sample binary.

```sh
gcc -g ./rust_sample.c -o rust_sample -lvade_evan -L../../target/debug/
```

### Execute the binary

once compiled run the binary

```sh
./rust_sample
```