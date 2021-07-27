// compile with gcc -g call_rust.c -o call_rust -lrustcalls -L./rustcalls/target/debug

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// sample struct to illustrate passing a C-struct to Rust
struct CStruct {
    char c;
    unsigned long ul;
    char *s;
};

// functions called in the Rust library
extern char * execute_vade(char * , char **, int, char *, char *);

int main() {
    char *args[] = {"did:ethr:mainnet:0x3b0BC51Ab9De1e5B7B6E34E5b960285805C41736"};
    char * response = execute_vade("did_resolve", args, 1, NULL, NULL);
    printf("\nrespnse %s  \n", response);
    return 0;
}
