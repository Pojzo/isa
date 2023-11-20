// Author: Peter Kovac
// login:  xkovac66
// 
// libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

// header files
#include "args.h"


// defines
#define return_free_client(args)\
    args_client_free(args);\
return NULL;

#define return_free_server(args)\
    args_server_free(args);\
return NULL

#define PRINT_LINE() printf("line: %d\n", __LINE__);
#define DEFAULT_PORT 69

const int MAX_HOST_LEN = 200;
const int MAX_PATH_LEN = 200;

static inline bool string_contains_char(char* string, char c) {
    char *p = string;
    while (p) {
        if (*p == c) {
            return true;
        }
        p++;
    }
    return false;
}

args_client_t* args_parse_client(int argc, char* argv[]) {
    int option = 0;
    args_client_t* args = args_client_create();
    if (args == NULL) {
        return NULL;
    }

    bool host_set = false;
    bool destination_set = false;

    while ((option = getopt(argc, argv, "h:p:f:t:")) != -1) {
        switch (option) {
            case 'h':
                if (strlen(optarg) > MAX_HOST_LEN) {
                    fprintf(stderr, "Host name too long\n");
                    return_free_client(args);
                }
                host_set = true;
                printf("host: %s\n", optarg);
                strcpy(args->host, optarg);
                break;
            case 'p':
                args->port = atoi(optarg);
                break;
            case 'f':
                if (strlen(optarg) > MAX_PATH_LEN) {
                    fprintf(stderr, "File path too long\n");
                    return_free_client(args);
                }
                printf("file path: %s\n", optarg);
                strcpy(args->filepath, optarg);
                args->download = true;
                break;
            case 't':
                if (strlen(optarg) > MAX_PATH_LEN) {
                    fprintf(stderr, "Destination file path too long\n");
                    return_free_client(args);
                }
                destination_set = true;
                printf("destination file path: %s\n", optarg);
                strcpy(args->destination_filepath, optarg);
                break;
            default:
                printf("default\n");
                fprintf(stderr, "Usage: %s -h <host> [-p <port>] -f <file_path> [-t <destination_file_path>]\n", argv[0]);
                return_free_client(args);
        }
    }
    if (!host_set || !destination_set) {
        fprintf("Destination set: %d\n", (int)destination_set);
        fprintf(stderr, "Usage: %s -h <host> [-p <port>] -f <file_path> [-t <destination_file_path>]\n", argv[0]);
        return_free_client(args);
    }

    return args;
}

args_client_t* args_client_create() {
    args_client_t *args = (args_client_t*) malloc(sizeof(args_client_t));
    if (args == NULL) {
        return NULL;
    }

    args->host = (char*) malloc(MAX_HOST_LEN * sizeof(char));
    args->host[0] = '\0';

    args->download = false;

    args->filepath = (char*) malloc(MAX_PATH_LEN * sizeof(char));
    args->filepath[0] = '\0';

    args->destination_filepath = (char*) malloc(MAX_PATH_LEN * sizeof(char));
    args->destination_filepath[0] = '\0';

    return args;
}

void args_client_free(args_client_t* args) {
    free(args->host);
    free(args->filepath);
    free(args->destination_filepath);
    free(args);
    args = NULL;
}

args_server_t* args_parse_server(int argc, char* argv[]) {
    args_server_t* args = (args_server_t*) malloc(sizeof(args_server_t));
    args->root_dirpath = (char *) malloc(MAX_PATH_LEN * sizeof(char));
    if (args == NULL) {
        return NULL;
    }
    args->port = DEFAULT_PORT;

    if (argc == 2) {
        strcpy(args->root_dirpath, argv[1]);
        return args;
    }
    if (argc == 4) {
        if (strcmp(argv[1], "-p") != 0) {
            fprintf(stdout, "Usage: %s [-p <port>] root_dirpath\n", argv[0]);
            return_free_server(args);
        }
        else {
            int port = atoi(argv[2]); 
            if (port < 1 || port > 65535) {
                fprintf(stdout, "Usage: %s [-p <port>] root_dirpath\n", argv[0]);
                return_free_server(args);
            }
            strcpy(args->root_dirpath, argv[3]);
            args->port = port;
            return args;
        }
    }

    return_free_server(args);
}

args_server_t * args_server_create(int argc, char* argv[]) {
    args_server_t* args = (args_server_t*) malloc(sizeof(args_server_t));
    args->root_dirpath = (char *) malloc(MAX_PATH_LEN * sizeof(char));

    return args;
}

void args_server_free(args_server_t *args) {
    free(args->root_dirpath);
    free(args);
    args = NULL;
}

