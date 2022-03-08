// compile with gcc -g call_rust.c -o call_rust -lrustcalls -L./rustcalls/target/debug

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// dummy function for request list
int resolve_http_request(void* vade_req_ctx, char* url, char* method, char* path, char* payload, char* res){

   return 0;
}


