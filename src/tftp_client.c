// Author: Peter Kovac
// login:  xkovac66
//
// libraries
#include <stdio.h> 
#include <string.h>    
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>

// header files
#include "args.h"
#include "utils.h"
#include "config.h"

// defines
#define DEBUG_PRINT(message) if (DEBUG) printf("%s\n", message);
#define ARGS_FREE_RETURN(args, message) \
    fprintf(stderr, "%s\n", message);   \
    args_client_free(args);             \
    return 1;

#define TFTP_PACKET_FREE_RETURN(packet, message) \
    tftp_packet_free(packet);                    \
    DEBUG_PRINT(message);                        \
    return 1;

#define DATA_LEN 512
#define INPUT_FILE_BUFFER_SIZE 100000


//prototypes
static int init_client(const char* host_ip, unsigned short port, struct sockaddr_in* server);
static int send_rrq   (int sock, struct sockaddr_in* server, const char* filename, const char* mode, char buffer[]);
static int send_wrq   (int sock, struct sockaddr_in* server, const char* filename, const char* mode, char buffer[]);

static int handle_download(const args_client_t *args, int sock, struct sockaddr_in server);

static int handle_upload(const args_client_t *args, int sock, struct sockaddr_in server);

int main(int argc, char *argv[]) {
    args_client_t *args = args_parse_client(argc, argv);

    if (args == NULL) {
        fprintf(stderr, "There was an error parsing arguments\n");
        return 1;
    }

    int filepath_set = args->download;
    printf("Filepath is %s\n", filepath_set ? "set" : "not set");

    struct sockaddr_in server;

    int sock = init_client(args->host, args->port, &server);

    if (sock == -1) {
        ARGS_FREE_RETURN(args, "Couldn't initialize the socket");
    }

    // downloading
    if (filepath_set) {
        if (handle_download(args, sock, server) == -1) {
            printf("There was an error downloading the file\n");
        }
        else {
            printf("File downloaded successfully\n");
        }
    }
    else {
        handle_upload(args, sock, server);
        // uploading
    }
    // close the socket 
    close(sock);
    args_client_free(args);

    return 0;
}

static int handle_download(const args_client_t *args, int sock, struct sockaddr_in server) {
    printf("Downloading file: %s\n", args->destination_filepath);
    struct sockaddr_in from;
    int msg_size, i;
    int len = sizeof(server);
    char rrq_buffer[100];

    // send rrq to the server
    int rrq = send_rrq(sock, &server, args->destination_filepath, "netascii", rrq_buffer);
    if (rrq == -1) {
        fprintf(stderr, "Couldn't send rrq\n");
        return 1;
    }

    unsigned char recv_buffer[100000];
    size_t recv_size;

    // receive requested file
    if (recv_file(sock, recv_buffer, from, &recv_size) == -1) {
        fprintf(stderr, "Couldn't receive file\n");
        return -1;
    }

    // store the downloaded file
    bytes_to_file(recv_buffer, recv_size, args->filepath, NULL);

    return;
    /*
       i = recvfrom(sock, recv_buffer, BUFFER_LEN, 0, (struct sockaddr *) &from, &len);

       if (getsockname(sock, (struct sockaddr*) &from, &len) == -1) {
       fprintf(stderr, "getsockname() in wrq failed\n");
       return 1;
       }
       if (i == -1) {
       fprintf(stderr, "recvfrom() failed\n");
       ARGS_FREE_RETURN(args, "recvfrom() failed");
       }
       else if(i > 0) {
       printf("* UDP packet received from %s, port %d (%d)\n",inet_ntoa(from.sin_addr),ntohs(from.sin_port), from.sin_port);

       printf("%.*s", i, recv_buffer);
       for (int x = 0; x < 100; x++) {
       printf("%c ",  recv_buffer[x]);
       }
       printf("\n");
       }
       if (recv_buffer[1] == ERR & 0xff) {
       printf("toto je error packet\n");
       }
       return 0;
       */
}

// upload file to the server
static int handle_upload(const args_client_t *args, int sock, struct sockaddr_in server) {
    // get the filename to upload from stdin

    unsigned char buffer[INPUT_FILE_BUFFER_SIZE];
    size_t input_len, bytes_read = 0;

    //static int send_wrq   (int sock, struct sockaddr_in* server, const char* filename, const char* mode, char buffer[]);


    while ((input_len = fread(buffer, sizeof(unsigned char) , INPUT_FILE_BUFFER_SIZE, stdin)) > 0) {
        bytes_read += input_len;
        printf("Read %ld bytes from stdin\n", bytes_read);
    }
    printf("bytes read: %d\n", bytes_read);
    char wrq_buffer[100];
    int wrq = send_wrq(sock, &server, args->destination_filepath, "netascii", wrq_buffer);
    if (wrq == -1) {
        fprintf(stderr, "Couldn't send wrq\n");
        return 1;
    }

    int server_len = sizeof(server);
    int ack_i = recvfrom(sock, wrq_buffer, 100, 0, (struct sockaddr *) &server, &server_len);
    if (ack_i == -1) {
        fprintf(stderr, "Couldn't receive ack\n");
        return -1;
    }
    unsigned short opcode = ntohs(*(unsigned short*) wrq_buffer);
    unsigned short block_number = ntohs(*(unsigned short*) (wrq_buffer + 2));

    if (opcode != ACK) {
        fprintf(stderr, "Received packet is not an ack\n");
        return -1;
    }
    if (block_number != 0) {
        fprintf(stderr, "Received ack is not for block 0\n");
        return -1;
    }
    printf("Received ack for wrq\n");

    send_file(sock, server, buffer, bytes_read, "octet", 512, 1);

    printf("Uploading [] file to: [%s]\n", args->destination_filepath);
    return 0;
}


// initialize the client, returns socket number on success, -1 if there was an error
static int init_client(const char* host_ip, unsigned short port, struct sockaddr_in* server) {
    int sock; 
    printf("toto je host_ip %s\n", host_ip);

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return -1;
    }
    (*server).sin_addr.s_addr = inet_addr(host_ip);
    (*server).sin_family = AF_INET;
    (*server).sin_port = htons(port);

    return sock;
}

static int send_rrq(int sock, struct sockaddr_in* server, const char* filename, const char* mode, char buffer[]) {
    int i, len;
    struct sockaddr_in from;
    printf("Sending rrq request for file: %s, mode: %s\n", filename, mode);

    len = sizeof(*server);
    tftp_packet_t* packet = tftp_packet_create(RRQ, filename, mode);

    unsigned char bytes[50];
    size_t msg_size;
    tftp_packet_to_bytes(bytes, packet, &msg_size);
    i = sendto(sock, bytes, msg_size, 0, (struct sockaddr*) server, len);
    tftp_packet_free(packet);
    if (i == -1) {
        TFTP_PACKET_FREE_RETURN(packet, "Write request not sent");
    }
    else if (i != msg_size) {
        TFTP_PACKET_FREE_RETURN(packet, "Write request sent partially");
    }
    if (getsockname(sock, (struct sockaddr*) &from, &len) == -1) {
        TFTP_PACKET_FREE_RETURN(packet, "getsockname() in wrq failed");
    }
    printf("Successfully sent rrq request for file: %s, mode: %s\n", filename, mode);

    return 0;
}

static int send_wrq(int sock, struct sockaddr_in* server, const char* filename, const char* mode, char buffer[]) {
    int i, len;
    struct sockaddr_in from;

    len = sizeof(*server);
    tftp_packet_t* packet = tftp_packet_create(WRQ, filename, mode);

    unsigned char bytes[50];
    size_t msg_size;
    tftp_packet_to_bytes(bytes, packet, &msg_size);
    i = sendto(sock, bytes, msg_size, 0, (struct sockaddr*) server, len);
    if (i == -1) {
        TFTP_PACKET_FREE_RETURN(packet, "Write request not sent");
    }
    else if (i != msg_size) {
        TFTP_PACKET_FREE_RETURN(packet, "Write request sent partially");
    }
    if (getsockname(sock, (struct sockaddr*) &from, &len) == -1) {
        TFTP_PACKET_FREE_RETURN(packet, "getsockname() in wrq failed");
    }
    printf("Successfully sent wrq request for file: %s, mode: %s\n", filename, mode);

    return 0;
}
