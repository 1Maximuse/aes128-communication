#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>

#include <gmp.h>

#include "aes.h"

void mpztobytearray(uint8_t* array, mpz_t data) {
    memset(array, 0, 128);
    for (int i = 127; i >= 0; i--) {
        mpz_t byte, mask;
        mpz_inits(byte, mask, NULL);
        mpz_set_ui(mask, 0xFF);
        mpz_and(byte, data, mask);

        array[i] = mpz_get_ui(byte);
        mpz_fdiv_q_2exp(data, data, 8);

        mpz_clears(byte, mask, NULL);
    }
}


void bytearraytompz(uint8_t* array, mpz_t data) {
    for (int i = 0; i < 128; i++) {
        mpz_mul_2exp(data, data, 8);
        mpz_add_ui(data, data, array[i]);
    }
}

void rsadecrypt(mpz_t d, mpz_t n, mpz_t input, uint8_t* output) {
    mpz_t decrypted;
    mpz_init(decrypted);
    mpz_powm_sec(decrypted, input, d, n);

    uint8_t decryptedbytes[128];
    mpztobytearray(decryptedbytes, decrypted);
    for (uint8_t i = 112; i < 128; i++) {
        output[i-112] = decryptedbytes[i];
    }
    mpz_clear(decrypted);
}

int recvdata(int conn_fd, char* filename, uint8_t* key) {
    FILE* f = fopen(filename, "wb");
    if (f == NULL) {
        printf("Cannot open file.\n");
        exit(1);
    }
    
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);

    uint8_t buffer[16];
    memset(buffer, 0, 16);
    uint32_t size = 0;
    ssize_t len;
    while ((len = recv(conn_fd, buffer, 16, 0)) == 16) {
        AES_ECB_decrypt(&ctx, buffer);
        fwrite(buffer, sizeof(uint8_t), 16, f);
        memset(buffer, 0, 16);
        size += len;
    }
    fclose(f);

    truncate(filename, size - buffer[0]);
}

void recvaeskey(int sock, mpz_t encrypted_data, mpz_t d, mpz_t n) {
    uint8_t buffer[128];
    memset(buffer, 0, 128);
    recv(sock, buffer, 128, 0);
    bytearraytompz(buffer, encrypted_data);
    memset(buffer, 0, 128);
    recv(sock, buffer, 128, 0);
    bytearraytompz(buffer, d);
    memset(buffer, 0, 128);
    recv(sock, buffer, 128, 0);
    bytearraytompz(buffer, n);
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

    // clock_t start, end;
    // start = clock();

    mpz_t encrypted_key, n, d;
    mpz_inits(encrypted_key, n, d, NULL);
    recvaeskey(sock_fd, encrypted_key, d, n);

    uint8_t key[16];
    rsadecrypt(d, n, encrypted_key, key);
    mpz_clears(encrypted_key, d, n, NULL);
    
    recvdata(sock_fd, argv[1], key);
    
    // end = clock();

    // double seconds = ((double)(end-start)) / CLOCKS_PER_SEC;
    // printf("%lf seconds.\n", seconds);

    close(sock_fd);
}