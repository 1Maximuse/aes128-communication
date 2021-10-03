#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>

#include "aes.h"

#define KEY { 0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98 }

int recvdata(int conn_fd, char* filename) {
    FILE* f = fopen(filename, "wb");
    if (f == NULL) {
        printf("Cannot open file.\n");
        exit(1);
    }
    
    uint8_t key[16] = KEY;
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);

    uint8_t buffer[16];
    memset(buffer, 0, 16);
    uint32_t size = 0;
    ssize_t len;
    while ((len = recv(conn_fd, buffer, 16, 0)) == 16) {
        // AES_ECB_decrypt(&ctx, buffer);
        fwrite(buffer, sizeof(uint8_t), 16, f);
        memset(buffer, 0, 16);
        size += len;
    }
    fclose(f);

    truncate(filename, size - buffer[0]);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("No filename specified.\n");
        exit(1);
    }

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        printf("Cannot create socket.\n");
        exit(1);
    }

    struct sockaddr_in srv_address;

    bzero(&srv_address, sizeof(struct sockaddr_in));
    srv_address.sin_family = AF_INET;
    srv_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    srv_address.sin_port = htons(10000);

    if (connect(sock_fd, (struct sockaddr*)&srv_address, sizeof(srv_address)) != 0) {
        printf("Cannot connect.\n");
        exit(1);
    }

    clock_t start, end;
    start = clock();
    recvdata(sock_fd, argv[1]);
    end = clock();

    double seconds = ((double)(end-start)) / CLOCKS_PER_SEC;
    printf("%lf seconds.\n", seconds);

    close(sock_fd);
}