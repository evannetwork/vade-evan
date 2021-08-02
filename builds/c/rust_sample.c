// compile with gcc -g call_rust.c -o call_rust -lrustcalls -L./rustcalls/target/debug

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>



// functions called in the Rust library
extern char * execute_vade(char *func_name , char **arguments, int num_of_args, char *options, char *config);

int main() {
    char *did_resolve_args[] = {"did:ethr:mainnet:0x3b0BC51Ab9De1e5B7B6E34E5b960285805C41736"};
    char *did_create_args[] = {"did:evan:testcore"};

    char *options = "{ \"identity\": \"did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906\", \"privateKey\": \"dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106\" }";

    char * response = execute_vade("did_resolve", did_resolve_args, 1, NULL, NULL); // calling did_resolve
    printf("response %s \n", response);


    response = execute_vade("did_create", did_create_args, 1, options, NULL); // calling did_create
    printf("response %s \n", response);

    return 0;
}
