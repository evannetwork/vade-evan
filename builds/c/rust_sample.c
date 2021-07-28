// compile with gcc -g call_rust.c -o call_rust -lrustcalls -L./rustcalls/target/debug

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>



// functions called in the Rust library
extern char * execute_vade(char *func_name , char **arguments, int num_of_args, char *options, char *config);

int main() {
    char *did_resolve_args[] = {"did:ethr:mainnet:0x3b0BC51Ab9De1e5B7B6E34E5b960285805C41736"};
    char *did_create_args[] = {"did:evan"};

    char *options = "{ identity: did:evan:testcore:0x3fd50CC762DC91F5440B8a530Db7B52813730596, privateKey: 270f69319fb71423d5f66f2a9d5f828536fa3c6108807449d4a541911b566b68, }";

    char * response = execute_vade("did_resolve", did_resolve_args, 1, NULL, NULL); // calling did_resolve
    printf("\nrespnse %s  \n", response);


    response = execute_vade("did_create", did_create_args, 1, options, NULL); // calling did_create
    printf("\nrespnse %s  \n", response);

    return 0;
}
