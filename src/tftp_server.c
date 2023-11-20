// Author: Peter Kovac
// login:  xkovac66
//
// libraries
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// header files
#include "args.h"
#include "utils.h"
#include "config.h"

// defines
#define DEBUG_PRINT(message) if (DEBUG) printf("%s\n", message);
#define ARGS_FREE_RETURN(args, message) \
    fprintf(stdout, "%s\n", message);   \
    args_server_free(args);             \
    return 1;

#define DATA_PACKET_LEN 516


// prototypes
static int init_server(unsigned short port, struct sockaddr_in* server);
static handle_rrq(const char *buffer, int fd, struct sockaddr_in client, const char *root_dirpath);
static handle_wrq(const char *buffer, int fd, struct sockaddr_in client, const char *root_dirpath);

int main(int argc, char *argv[]) {
    args_server_t *args = args_parse_server(argc, argv);

    if (args == NULL) {
        fprintf(stdout, "There was an error parsing arguments\n");
        // args_server_free(args);
        return 1;
    }
    printf("root dirpath: %s\n", args->root_dirpath);

    struct sockaddr_in server;
    int fd = init_server(args->port, &server);
    if (fd == -1) {
        fprintf(stdout, "Couldn't start the server\n");
        args_server_free(args);
        return 1;
    }
    printf("Successfully bound\nport: %d\n", args->port);
    int msg_size, i;
    struct sockaddr_in client;
    socklen_t length;
    char buffer[WRQ_BUFFER_LEN];

    length = sizeof(client);
    while (true) {
        msg_size = recvfrom(fd, buffer, WRQ_BUFFER_LEN, 0, (struct sockaddr *) &client, &length);
        // fork the process
        if (msg_size == -1) {
            continue;
        }

        printf("Requests received from %s, port %d, msg_size: %d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port), msg_size);

        if (buffer[1] == RRQ) {
            handle_rrq(buffer, fd, client, args->root_dirpath);
        }
        else if (buffer[1] == WRQ) {
            handle_wrq(buffer, fd, client, args->root_dirpath);
        }
    }

    close(fd);
    args_server_free(args);

    return 0;
}

// initialize the server, returns socket on success, otherwise -1
static int init_server(unsigned short port, struct sockaddr_in* server) {
    int fd;
    (*server).sin_family      = AF_INET;
    (*server).sin_addr.s_addr = htonl(INADDR_ANY);
    (*server).sin_port        = htons(port);
    (void) port;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        DEBUG_PRINT("fd failed");
        return -1;
    }
    if (bind(fd, (struct sockaddr *) server, sizeof(*server)) == -1)  {
        DEBUG_PRINT("bind failed");
        return -1;
    }

    return fd;
}


static int handle_rrq(const char *buffer, int fd, struct sockaddr_in client, const char *root_dirpath) {
    printf("\n");
    printf("Handling RRQ\n");
    unsigned char packet_bytes[WRQ_BUFFER_LEN];

    tftp_packet_t *packet = bytes_to_tftp_packet(buffer);

    const char *source_ip = inet_ntoa(client.sin_addr);
    const unsigned short source_port = ntohs(client.sin_port);

    const char *filename = packet->filename;
    const char *mode = packet->mode;

    print_rrq(source_ip, source_port, filename, mode);
    if (packet->blksize_option) {
        print_option("blksize", packet->blksize);
    }
    if (packet->timeout_option) {
        print_option("timeout", packet->timeout);
    }

    const char filepath[100];
    strcpy(filepath, root_dirpath);
    strcat(filepath, "/");
    strcat(filepath, filename);
    printf("filepath: %s\n", filepath);

    if (file_exists(filepath)) {
        printf("File exists\n");
        //
        // //send oack
        int blksize_option = packet->blksize_option ? packet->blksize : -1;
        int timeout_option = packet->timeout_option ? packet->timeout : -1;

        if (blksize_option == -1 && timeout_option == -1) {
            send_file_from_filename(fd, client, filepath, packet->mode, packet->blksize, packet->timeout);
        }
        else {
            if (send_oack(fd, client, blksize_option, timeout_option) != -1) {
                // recv ack block 0 
                unsigned char ack_buffer[4];
                recvfrom(fd, ack_buffer, 4, 0, (struct sockaddr *) &client, &(socklen_t) {sizeof(client)});
                return send_file_from_filename(fd, client, filepath, packet->mode, packet->blksize, packet->timeout);
            }
        }
    }
    else {
        const int buffer_size = 100;
        unsigned err_buff[buffer_size];
        const char *err_msg = "The requested file was not found";
        unsigned int msg_len = strlen(err_msg);

        error_to_bytes(err_buff, FILE_NOT_FOUND, err_msg, msg_len);

        int msg_size = 4 + msg_len + 1;

        printf("error msg_size: %d\n", msg_size);
        int length = sizeof(client);
        int i = sendto(fd, err_buff, msg_size, 0, (struct sockaddr*) &client, length);
        if (i == -1) {
            tftp_packet_free(packet);
            return 1;
        }
        else if (i != msg_size) {
        }
    }
    // printf("Freeing packet\n");
    tftp_packet_free(packet);
    return 0;
}

static handle_wrq(const char *buffer, int fd, struct sockaddr_in client, const char *root_dirpath) {
    printf("Handling WRQ\n");
    tftp_packet_t *packet = bytes_to_tftp_packet(buffer);
    const char *filename = packet->filename;
    const char *mode = packet->mode;

    const char *source_ip = inet_ntoa(client.sin_addr);
    const unsigned char source_port = ntohs(client.sin_port);

    print_wrq(source_ip, source_port, filename, mode);

    const char RECV_BUFFER[100000];
    size_t final_len;
    send_ack(fd, client, 0);
    printf("Sent ack for WRQ\n");
    recv_file(fd, RECV_BUFFER, client, &final_len);
    bytes_to_file(RECV_BUFFER, final_len, filename, root_dirpath);
}
