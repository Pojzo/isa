// Author: Peter Kovac
// login:  xkovac66
//
// libraries
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

// haeder files
#include "utils.h"
#include "config.h"
#include <unistd.h>

// defines
#define OPCODE_BYTES    2
#define MODE_LEN        10
#define ACK_PACKET_LEN  4

#define DATA_LEN        512
#define DATA_PACKET_LEN 516

// constructor for tftp_packet_t
tftp_packet_t* tftp_packet_create(OPCODE opcode, const char* filename, const char* mode) {
    tftp_packet_t *packet = (tftp_packet_t*) malloc(sizeof(tftp_packet_t));
    packet->filename = (char*) malloc(((FILENAME_LEN + 1)* sizeof(char)));
    packet->mode     = (char*) malloc(((MODE_LEN  +1)        * sizeof(char)));

    packet->opcode = opcode;

    strncpy(packet->filename, filename, FILENAME_LEN);
    packet->filename[FILENAME_LEN - 1] = '\0';


    if (mode[0] == 'n') {
        strcpy(packet->mode, "netascii");

    } else if (mode[0] == 'o') {
        strcpy(packet->mode, "octet");
    }

    packet->blksize_option = false;
    packet->blksize = DATA_LEN;

    packet->timeout_option = false;
    packet->timeout = 10;

    return packet;
}

// destructor for tftp_packet_t
void tftp_packet_free(tftp_packet_t* packet) {
    free(packet->filename);
    free(packet->mode);
    free(packet);
    packet = NULL;
}

// convert received tftp_packet_t structure to bytes
void tftp_packet_to_bytes(unsigned char buffer[], tftp_packet_t* packet, size_t *num_bytes) {
    buffer[0] = 0x00;
    buffer[1] = packet->opcode & 0xFF;

    unsigned int filename_len = strlen(packet->filename);
    unsigned int offset = OPCODE_BYTES;

    // filename
    memcpy(buffer + offset, packet->filename, filename_len);
    offset += filename_len;

    // 1 byte
    buffer[offset] = '\0';

    unsigned int mode_len = strlen(packet->mode);
    offset += 1;

    // mode
    memcpy(buffer + offset, packet->mode, mode_len);

    // 1 byte
    offset += mode_len + 1;

    /*
    // blksize option
    const char *blksize_opt = "blksize";
    memcpy(buffer + offset, blksize_opt, 7);
    buffer[offset + 7] = '\0';
    offset += 7 + 1;

    const char *default_blksize = "512";
    memcpy(buffer + offset, default_blksize, 3);
    buffer[offset + 3] = '\0';
    offset += 3 + 1;

    *num_bytes = offset;
    // timeout option
    const char *timeout_opt = "timeout";
    memcpy(buffer + offset, timeout_opt, 7);
    buffer[offset + 7] = '\0';
    offset += 7 + 1;

    const char *default_timeout = "10";
    memcpy(buffer + offset, default_timeout, strlen(default_timeout));
    buffer[offset + strlen(default_timeout)] = '\0';
    offset += strlen(default_timeout) + 1;

    */
    *num_bytes = offset;

}

// convert bytes from buffer to tftp_packet_t structure
tftp_packet_t* bytes_to_tftp_packet(unsigned char buffer[]) {
    OPCODE opcode = buffer[1];
    int offset = -1;
    for (unsigned int i = 2; i < 2 + FILENAME_LEN; i++) {
        if (buffer[i] == 0x00) {
            offset = i;
            break;
        }
    }
    if (offset == -1) return NULL;
    unsigned int filename_len = offset - 2;
    char filename[filename_len + 1];
    memcpy(filename, buffer + 2, filename_len);
    filename[filename_len] = '\0';

    unsigned int filename_offset = 2 + filename_len + 1;

    int mode_offset = -1;
    for (unsigned int i = filename_offset; i < filename_offset + FILENAME_LEN; i++) {
        if (buffer[i] == 0x00) {
            mode_offset = i;
            break;
        }
    }
    if (offset == offset + FILENAME_LEN - 1) return NULL;
    unsigned int mode_len = mode_offset - filename_offset;
    char mode[mode_len];
    memcpy(mode, buffer + filename_offset, mode_len);
    mode[mode_len] = '\0';

    tftp_packet_t *packet = tftp_packet_create(opcode, filename, mode);

    offset = mode_offset + 1;

    const char *blksize_opt = "blksize";
    const char *timeout_opt = "timeout";
    // parse options
    while (!(buffer[offset] == 0x00 && buffer[offset + 1] == 0x00)) {
        if (strncmp(buffer + offset, blksize_opt, 7) == 0) {
            packet->blksize_option = true;
            packet->blksize = atoi((char*) buffer + offset + 8);
            if (packet->blksize < 8 || packet->blksize > 65464) {
                packet->blksize = DATA_LEN;
            }

        } else if (strncmp(buffer + offset, timeout_opt, 7) == 0) {
            packet->timeout_option = true;
            packet->timeout = atoi((char*) buffer + offset + 8);
            if (packet->timeout < 1 || packet->timeout > 255) {
                packet->timeout = 10;
            }
        }
        offset += strlen((char*) buffer + offset) + 1;  
    }

    return packet;
}

void print_bits(unsigned char bytes[], unsigned int length) {
    for (unsigned int i = 0; i < length; i++) {
        unsigned char byte = bytes[i];
        for (int j = 7; j >= 0; j--) {
            int bit = (byte >> j) & 1;
            printf("%d", bit);
        }
        printf(" ");  // Add a space between bytes for readability
                      //     }
                      //         printf("\n");
                      //         }
        }
}

bool file_exists(const char *filename) {
    return !access(filename, F_OK);
}

// convert error code and error message to bytes
void error_to_bytes(unsigned char buffer[], ERROR_CODE error_code, const char* err_msg, unsigned int msg_len) {
    buffer[0] = 0x00;
    buffer[1] = ERR & 0xff;

    buffer[2] = 0x00;
    buffer[3] = error_code & 0xff;

    strncpy((char*) (buffer + 4), err_msg, msg_len);
    buffer[4 + msg_len] = '\0';
}

// send error given error code and error message
int send_error(int sock, struct sockaddr_in to, ERROR_CODE error_code, const char* err_msg) {
    unsigned char error_packet[WRQ_BUFFER_LEN];
    error_to_bytes(error_packet, error_code, err_msg, strlen(err_msg));

    int length = sizeof(to);
    int i = sendto(sock, error_packet, strlen(err_msg) + 5, 0, (struct sockaddr*) &to, length);
    if (i == -1) {
        fprintf(stdout, "sendto() failed\n");
        return -1;
    }
    return 0;
}

// convert data packet to buffer
void data_packet_to_bytes(unsigned char buffer[], unsigned short block_num, const unsigned char *data, size_t data_len) {
    buffer[0] = 0x00;
    buffer[1] = DATA & 0xff;

    buffer[2] = (block_num >> 8) & 0xff;
    buffer[3] = block_num & 0xff;

    memcpy(buffer + 4, data, data_len);
}

// convert buffer data to segments
unsigned char **data_to_segments(const unsigned char *data, size_t bytes_len, size_t *num_segments, size_t block_size) {
    *num_segments = bytes_len / block_size;
    if (bytes_len % block_size != 0) {
        (*num_segments)++;
    }
    // printf("Number of segments: %d\n", (int) *num_segments);
    unsigned char **segments = (unsigned char **) malloc(*num_segments * sizeof(unsigned char *));

    size_t offset;
    for (size_t i = 0; i < *num_segments - 1; i++) {
        offset = i * block_size;
        segments[i] = (unsigned char *) malloc(block_size * sizeof(unsigned char));
        memcpy(segments[i], data + offset, block_size);
    }
    offset = (*num_segments -1) *  block_size;
    size_t remainder = bytes_len % block_size;
    segments[*num_segments - 1] = (unsigned char *) malloc(remainder * sizeof(unsigned char));
    // printf("toto je remainder %d\n", remainder);
    memcpy(segments[*num_segments - 1], data + offset, remainder);
    for (int x = 0; x < remainder; x++) {
        // printf("%c ", segments[(*num_segments) - 1][x]);
    }

    return segments;
}

// convert segments to data
unsigned char *segments_to_data(const unsigned char **segments, size_t num_segments) {
    unsigned char *data = (unsigned char * )malloc(num_segments * DATA_LEN * sizeof(unsigned char));
}

// free segments
void free_segments(const unsigned char **segments, size_t num_segments) {
    for (size_t i = 0; i < num_segments; i++) {
        free(segments[i]);
        segments[i] = NULL;
    }
    free(segments);
    segments = NULL;
}

// read file from filename, store it inside a buffer and send it to the server
unsigned char *file_to_bytes(const char *filename, size_t *buffer_len) {
    FILE *fileptr;
    char *buffer;
    long filelen;

    if((fileptr = fopen(filename, "rb")) == NULL) {
        return NULL;
    }
    fseek(fileptr, 0, SEEK_END);
    filelen = ftell(fileptr);
    rewind(fileptr);
    *buffer_len = filelen;

    buffer = (unsigned char *) malloc((filelen + 1)* sizeof(unsigned char));
    buffer[filelen] = '\0';
    fread(buffer, filelen, 1, fileptr);

    fclose(fileptr);
    return buffer;
}


// write bytes from buffer to file
int bytes_to_file(const unsigned char *bytes, size_t len, const char *filename, const char *root_dirpath) {
    FILE *fileptr;
    const char filepath[100];
    if (root_dirpath == NULL) {
        strcpy(filepath, filename);

    } else {
        strcpy(filepath, root_dirpath);
        strcat(filepath, "/");
        strcat(filepath, filename);
    }

    if ((fileptr = fopen(filepath, "wb+")) == NULL) {
        return 1;
    }
    printf("Writing bytes to %s\n", filepath);
    for (int i = 0; i < len; i++) {
        unsigned char cur_char = bytes[i];
        // printf("%c ", cur_char);
        fwrite(&cur_char, 1, sizeof(cur_char), fileptr);
    }
    fclose(fileptr);
    printf("\n");
}

// read file from filename, store it inside a buffer and send it to the server
int send_file_from_filename(int fd, struct sockaddr_in client, const char *filename, const char *mode, size_t block_size, size_t timeout) {

    // if (DEBUG) printf("Sending file: %s\n", filename);
    size_t buffer_len;
    unsigned char *file_buffer = file_to_bytes(filename, &buffer_len);
    if (file_buffer == NULL) {
        printf("File not found\n");
        return 1;
    }
    printf("Sending file %s %d\n", filename, buffer_len);

    int return_value = send_file(fd, client, file_buffer, buffer_len, mode, block_size, timeout);
    free(file_buffer);
    return return_value;
}

// convert buffer from octet to netascii format
static unsigned char *convertToNetascii(const unsigned char *buffer, size_t length, size_t *new_length) {
    size_t estimated_length = length * 2;
    unsigned char *new_buffer = (unsigned char *) malloc(estimated_length * sizeof(unsigned char));
    if (new_buffer == NULL) {
        return NULL;
    }
    size_t new_buffer_index = 0;
    for (size_t i = 0; i<  length; i++) {
        if (buffer[i] == '\n') {
            new_buffer[new_buffer_index++] = '\r';

            if (new_buffer_index >= estimated_length) {
                estimated_length *= 2;
                new_buffer = (unsigned char *) realloc(new_buffer, estimated_length * sizeof(unsigned char));
                if (new_buffer == NULL) {
                    return NULL;
                }
            }
        }
        new_buffer[new_buffer_index++] = buffer[i];
        if (new_buffer_index >= estimated_length) {
            estimated_length *= 2;
            new_buffer = (unsigned char *) realloc(new_buffer, estimated_length * sizeof(unsigned char));
            if (new_buffer == NULL) {
                return NULL;
            }
        }
    }
    *new_length = new_buffer_index;
    return new_buffer;
}



// send file to the client, if needed, convert it to netascii
int send_file(int fd, struct sockaddr_in client, unsigned char *buffer, size_t buffer_len, const char *mode, size_t block_size, size_t timeout) {
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    const int DEBUG = 0;

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    if (DEBUG) printf("Timeout: %d\n", (int) timeout);
    unsigned char *netascii_buffer = NULL;

    if (strcmp(mode, "netascii") == 0) {
        size_t new_buffer_len;
        netascii_buffer = convertToNetascii(buffer, buffer_len, &new_buffer_len);
        if (netascii_buffer == NULL) {
            return 1;
        }
        buffer = netascii_buffer;
        buffer_len = new_buffer_len;
    }

    unsigned char *file_buffer;
    file_buffer = buffer;

    size_t num_segments;
    unsigned char **segments = data_to_segments(file_buffer, buffer_len, &num_segments, block_size);
    size_t last_block_len = buffer_len % block_size + 4;
    if (DEBUG) printf("Number of segments: %d%d\n", (int) num_segments, DEBUG);
    int length = sizeof(client);
    for (size_t s = 1; s <= num_segments; s++) {
        size_t packet_len = s == num_segments ? last_block_len : block_size + 4;
        unsigned char data_packet[packet_len];
        if (DEBUG) printf("Sending segment: %d\npacket size: %d\n", s, packet_len);

        data_packet_to_bytes(data_packet, s, segments[s - 1], packet_len);

        int i = sendto(fd, data_packet, packet_len, 0, (struct sockaddr*) &client, length);

        unsigned char ack[ACK_PACKET_LEN];
        i = recvfrom(fd, ack, ACK_PACKET_LEN, 0, (struct sockaddr *) &client, &length);
        if (i < 0) {
            send_error(fd, client, 0, "Timeout");
            printf("Timeout\n");
            goto end_error;
        }

        if (DEBUG) printf("Received ack: %d\n", s);
        unsigned short opcode = (ack[0] << 8) | ack[1];
        if (opcode != ACK) {
            printf("Wrong opcode\n");
            goto end_error;
        }
        unsigned short block_num = (ack[2] << 8) | ack[3];
        if (block_num != s) {
            printf("Wrong block num, got %d, expected %d\n", block_num, s);
            goto end_error;
        }

        unsigned short source_port = ntohs(client.sin_port);
        const char *source_ip = inet_ntoa(client.sin_addr);

        // printf("source port: %d\n", source_port);
        // printf("source ip: %s\n", source_ip);
        print_ack(inet_ntoa(client.sin_addr), source_port, s);
    }
    if (netascii_buffer != NULL) {
        free(netascii_buffer);
    }
    goto end_good;

end_error:
    free_segments((const unsigned char **) segments, num_segments);
    if (netascii_buffer != NULL) {
        free(netascii_buffer);
    }
    return 1;

end_good:
    free_segments((const unsigned char **) segments, num_segments);
    return 0;
}


// recv file from the client and save it to the buffer
int recv_file(int fd, unsigned char full_buffer[], struct sockaddr_in from, size_t *final_len) {
    int len = sizeof(from);
    int last_len = 0;
    short block_num;
    int offset = 0;
    char packet_buffer[WRQ_BUFFER_LEN];
    while (1) {
        int i = recvfrom(fd, packet_buffer, WRQ_BUFFER_LEN, 0, (struct sockaddr *) &from, &len);
        // get first two bytes from buffer
        short opcode = (packet_buffer[0] << 8) | packet_buffer[1];
        if (opcode == ERR) {
            printf("Error packet received\n");
            short error_code = (packet_buffer[2] << 8) | packet_buffer[3];
            unsigned char error_msg_buffer[100];
            int i = 0;
            while (i < 100 && packet_buffer[i + 4] != '\0') {
                error_msg_buffer[i] = packet_buffer[i + 4];
                i++;
            }
            error_msg_buffer[i] = '\0';
            printf("Error code: %d\n", error_code);
            printf("Error message: %s\n", error_msg_buffer);
            return -1;
        }
        block_num = (packet_buffer[2] << 8) | packet_buffer[3];
        memcpy(full_buffer + offset, packet_buffer + 4, i - 4);
        offset += i - 4;
        printf("Received block num: %d and %d bytes\noffset - %d\n", block_num, i, offset);
        // send ack packet 
        int send_i = send_ack(fd, from, (unsigned int) block_num);
        printf("Sending ack: %d\n", block_num);

        const char *source_ip = inet_ntoa(from.sin_addr);
        const unsigned short source_port = ntohs(from.sin_port);
        const unsigned short destination_port = ntohs(from.sin_port);

        print_data(source_ip, source_port, destination_port, block_num);

        if (i != DATA_LEN + 4) {
            last_len = i - 4;
            break;
        }

        block_num++;
    }
    *final_len = (block_num -1)* DATA_LEN + last_len;
    printf("Received %d bytes\n", (block_num -1 )* DATA_LEN + last_len);

    return 0;
}

// send ack packet
int send_ack(int sock, struct sockaddr_in to, unsigned short block_num) {
    unsigned char ack_packet[4];
    ack_packet[0] = 0x00;
    ack_packet[1] = ACK & 0xff;

    ack_packet[2] = block_num >> 8;
    ack_packet[3] = block_num & 0xff;

    int length = sizeof(to);
    int i = sendto(sock, ack_packet, 4, 0, (struct sockaddr*) &to, length);
    if (i == -1) {
        fprintf(stdout, "sendto() failed\n");
        return 1;
    }
    return 0;
}

// send option acknowledgement packet
int send_oack(int sock, struct sockaddr_in to, int blksize, int timeout) {
    size_t len = 2;
    unsigned char oack_packet[WRQ_BUFFER_LEN];
    oack_packet[0] = 0x00;
    oack_packet[1] = OACK & 0xff;

    printf("blksize: %d\n", blksize);
    const char blksize_str[10];
    const char timeout_str[10];
    sprintf(blksize_str, "%d", blksize);
    sprintf(timeout_str, "%d", timeout);
    if (blksize != -1) {
        const char *blksize_opt = "blksize";
        strncpy(oack_packet + len, blksize_opt, 8);
        len += 8;
        strncpy(oack_packet + len, blksize_str, strlen(blksize_str));
        len += strlen(blksize_str);
        oack_packet[len++] = '\0';
    }

    if (timeout != -1) {
        strncpy(oack_packet + len, "timeout", 8);
        len += 8;
        strncpy(oack_packet + len, timeout_str, strlen(timeout_str));
        len += strlen(timeout_str);
        oack_packet[len++] = '\0';
    }

    int i = sendto(sock, oack_packet, len, 0, (struct sockaddr*) &to, sizeof(to));
    if (i == -1) {
        fprintf(stdout, "sendto() failed\n");
        return 1;
    }
}

// define if to print to stdout or stdout 
#define PRINT_OUTPUT stderr

void print_rrq(const char *source_ip, unsigned short source_port, const char *filename, const char *mode) {
    fprintf(PRINT_OUTPUT, "RRQ %s:%d \"%s\" %s\n", source_ip, source_port, filename, mode);
}

void print_option(const char *name, unsigned int value) {
    fprintf(PRINT_OUTPUT, "%s=%d\n", name, (int)value);
}

void print_wrq(const char *source_ip, unsigned short source_port, const char *filename, const char *mode) {
    fprintf(PRINT_OUTPUT, "WRQ %s:%d \"%s\" %s\n", source_ip, source_port, filename, mode);
}

void print_ack(const char *source_ip, unsigned short source_port, size_t block_num) {
    fprintf(PRINT_OUTPUT, "ACK %s:%d %d\n", source_ip, source_port, block_num);
}

void print_error(const char *source_ip, unsigned short source_port, unsigned short destination_port, ERROR_CODE error_code, const char *err_msg) {
    fprintf(PRINT_OUTPUT, "ERROR %s:%d:%d %d \"%s\"\n", source_ip, source_port, destination_port, error_code, err_msg);
}

void print_data(const char *source_ip, unsigned short source_port, unsigned short destination_port, size_t block_num) {
    fprintf(PRINT_OUTPUT, "DATA %s:%d:%d %d\n", source_ip, source_port, destination_port, block_num);
}
