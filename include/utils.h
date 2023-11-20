// Author: Peter Kovac
// login:  xkovac66
//
#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <netinet/in.h>

typedef enum {
    RRQ  = 1,
    WRQ  = 2,     
    DATA = 3,
    ACK  = 4,
    ERR  = 5,
    OACK = 6
} OPCODE;

typedef enum {
    NOT_DEFINED = 0, 
    FILE_NOT_FOUND = 1,
    ACCESS_VIOLATION = 2,
    DISK_FULL = 3,
    ILLEGAL_OP = 4,
    UNKNOWN_ID = 5,
    FILE_EXISTS = 6,
    UNKNOWN_USER = 7
} ERROR_CODE;

// structure for storing read-write packets
typedef struct {
    OPCODE       opcode;
    char*        filename;
    char*        mode;

    bool         blksize_option;
    size_t       blksize;

    bool         timeout_option;
    size_t       timeout;

} tftp_packet_t;

// prototypes
tftp_packet_t* tftp_packet_create(OPCODE opcode, const char* filename, const char* mode);
void free_tftp_free(tftp_packet_t* packet);
void tftp_packet_to_bytes(unsigned char buffer[], tftp_packet_t* packet, size_t *num_bytes);
tftp_packet_t* bytes_to_tftp_packet(unsigned char buffer[]);

void error_to_bytes(unsigned char buffer[], ERROR_CODE error_code, const char* err_msg, unsigned int msg_len);

void print_bits(unsigned char bytes[], unsigned int length);
bool file_exists(const char *filename);

unsigned char *file_to_bytes(const char *filename, size_t *buffer_len);
int bytes_to_file(const unsigned char *bytes, size_t len, const char *filename, const char*);

unsigned char **data_to_segments(const unsigned char *data, size_t bytes_len, size_t *num_segments, size_t blksize);
void free_segments(const unsigned char **segments, size_t num_segments);
unsigned char *segments_to_data(const unsigned char **segments, size_t num_segments);

int recv_file(int fd, unsigned char buffer[], struct sockaddr_in from, size_t *final_len);
int send_file_from_filename(int fd, struct sockaddr_in client, const char *filename, const char *mode, size_t blksize, size_t timeout);

int send_file(int fd, struct sockaddr_in client, unsigned char* buffer, size_t len, const char *mode, size_t blksize, size_t timeout);
int send_ack(int sock, struct sockaddr_in to, unsigned short block_num);
int send_oack(int sock, struct sockaddr_in to, int blksize, int timeout);

void print_rrq(const char *source_ip, unsigned short source_port, const char *filename, const char *mode);
void print_wrq(const char *source_ip, unsigned short source_port, const char *filename, const char *mode);
void print_ack(const char *source_ip, unsigned short source_port, size_t block_num);
void print_error(const char *source_ip, unsigned short source_port, unsigned short destination_port, ERROR_CODE error_code, const char *err_msg);
void print_data(const char *source_ip, unsigned short source_port, unsigned short destination_port, size_t block_num);
void print_option(const char *name, unsigned int value);

int send_error(int sock, struct sockaddr_in to, ERROR_CODE error_code, const char* err_msg);

#endif
