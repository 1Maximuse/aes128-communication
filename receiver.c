#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

int recvdata(int conn_fd, char* filename) {
    FILE* f = fopen(filename, "wb");
    if (f == NULL) {
        printf("Cannot open file.\n");
        exit(1);
    }
    uint8_t buffer[16];
    memset(buffer, 0, 16);
    ssize_t len;
    while ((len = recv(conn_fd, buffer, 16, 0)) > 0) {
        fwrite(buffer, sizeof(uint8_t), len, f);
        memset(buffer, 0, 16);
    }
    fclose(f);
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

    recvdata(sock_fd, argv[1]);

    close(sock_fd);
}