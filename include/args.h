// Author: Peter Kovac
// login:  xkovac66

#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include <stdbool.h>

extern const int MAX_HOST_LEN;
extern const int MAX_PATH_LEN;

// structures for storing command line argument

// client command line arguments
typedef struct {
    char*          host;
    unsigned short port;
    bool           download;
    char*          filepath; // destination path download/upload
    char*          destination_filepath;

} args_client_t;

// server command line arguments
typedef struct {
    unsigned short port;
    char*          root_dirpath;
} args_server_t;

// prototypes for client arguments
args_client_t* args_parse_client(int argc, char* argv[]); 
args_client_t* args_client_create();
void           args_client_free(args_client_t* args);

// prototypes for server arguments
args_server_t* args_parse_server(int argc, char* argv[]);
args_server_t* args_server_create();
void           args_server_free(args_server_t* args);


#endif
