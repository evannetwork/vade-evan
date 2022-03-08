# Sample C code to use vade-evan

## About

This sample code demonstrates how to call vade functions from C code


### How to build

```sh
gcc -g ./builds/c/rust_sample.c -o rust_sample -lvade_evan -L../vade-evan/target/debug/
```

### Execute the binary

once compiled run the binary

```sh
./rust_sample
```

### Building dummy request list function

```sh
gcc ./builds/c/request_list_dummy.c -c -o request_list.o
ar rcs librequest_list.dylib request_list.o
```
