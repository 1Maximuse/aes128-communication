#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include "aes.h"

// https://www.random.org/cgi-bin/randbyte?nbytes=16&format=h
#define KEY { 0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98 }

int senddata(int conn_fd, char* filename) {
    FILE* f = fopen(filename, "rb");
    if (f == NULL) {
        printf("Cannot open file.\n");
        exit(1);
    }
    
    uint8_t key[16] = KEY;
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);

    uint8_t buffer[16];
    memset(buffer, 0, 16);
    size_t len;
    uint8_t buflength;
    while ((len = fread(buffer, sizeof(uint8_t), 16, f)) > 0) {
        AES_ECB_encrypt(&ctx, buffer);
        send(conn_fd, buffer, 16, 0);
        memset(buffer, 0, 16);
        buflength = 16 - len;
    }
    fclose(f);
    send(conn_fd, &buflength, 1, 0);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("No file specified.\n");
        exit(1);
    }

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        printf("Cannot create socket.\n");
        exit(1);
    }
    
    int opt = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in srv_address, cli_address;

    bzero(&srv_address, sizeof(struct sockaddr_in));
    srv_address.sin_family = AF_INET;
    srv_address.sin_addr.s_addr = htonl(INADDR_ANY);
    srv_address.sin_port = htons(10000);

    if (bind(sock_fd, (struct sockaddr*)&srv_address, sizeof(struct sockaddr_in)) != 0) {
        printf("Cannot bind socket to address.\n");
        exit(1);
    }

    if (listen(sock_fd, 1) != 0) {
        printf("Cannot listen for connections.\n");
        exit(1);
    }

    socklen_t cli_address_size = sizeof(cli_address);
    int conn_fd = accept(sock_fd, (struct sockaddr*)&cli_address, &cli_address_size);
    if (conn_fd == -1) {
        printf("Cannot accept connection. %d\n", errno);
        exit(1);
    }

    clock_t start, end;
    start = clock();
    senddata(conn_fd, argv[1]);
    end = clock();

    double seconds = ((double)(end-start)) / CLOCKS_PER_SEC;
    printf("%lf seconds.\n", seconds);

    close(conn_fd);
    close(sock_fd);
}