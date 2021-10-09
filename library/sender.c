#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <gmp.h>

#include "aes.h"

#define RSA_KEY_LENGTH 1024

int senddata(int conn_fd, char* filename, uint8_t* aeskey) {
    FILE* f = fopen(filename, "rb");
    if (f == NULL) {
        printf("Cannot open file.\n");
        exit(1);
    }
    
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, aeskey);

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

void generateaeskey(uint8_t* key) {
    for (uint8_t i = 0; i < 16; i++) {
        key[i] = rand() & 0xFF;
    }
}

void generateprime(mpz_t number, gmp_randstate_t rstate) {
    mpz_ui_pow_ui(number, 2, (RSA_KEY_LENGTH >> 1) - 1);
    while (1) {
        mpz_t randn, addn;
        mpz_inits(randn, addn, NULL);
        mpz_urandomb(randn, rstate, (RSA_KEY_LENGTH >> 1) - 1);
        mpz_add(addn, number, randn);

        if (mpz_probab_prime_p(addn, 40)) {
            mpz_set(number, addn);
            mpz_clears(randn, addn, NULL);
            return;
        }

        mpz_clears(randn, addn, NULL);
    }   
}

void phi(mpz_t out, mpz_t p, mpz_t q){
    mpz_t pmin, qmin;
    mpz_inits(pmin, qmin, NULL);
    mpz_sub_ui(pmin, p, 1);
    mpz_sub_ui(qmin, q, 1);
    mpz_mul(out, pmin, qmin);
    mpz_clears(pmin, qmin, NULL);
}

void generaterelativelyprime(mpz_t out, mpz_t phin, gmp_randstate_t rstate) {
    mpz_urandomm(out, rstate, phin);
    
    while (1) {
        mpz_t gcd;
        mpz_init(gcd);
        mpz_gcd(gcd, phin, out);

        if (mpz_get_ui(gcd) == 1) {
            mpz_clear(gcd);
            return;
        }
        mpz_urandomm(out, rstate, phin);
        mpz_clear(gcd);
    }
}

void generatersakeypair(mpz_t d, mpz_t e, mpz_t n) {
    unsigned long seed = time(0);
    gmp_randstate_t rstate;
    gmp_randinit_mt(rstate);
    gmp_randseed_ui(rstate, seed);

    mpz_t p, q;
    mpz_inits(p, q, NULL);
    generateprime(p, rstate);
    generateprime(q, rstate);

    mpz_mul(n, p, q);
    mpz_t phin;
    mpz_init(phin);
    phi(phin, p, q);
    generaterelativelyprime(e, phin, rstate);
    mpz_clears(p, q, NULL);

    mpz_invert(d, e, phin);

    gmp_randclear(rstate);
}

void rsaencrypt(mpz_t e, mpz_t n, uint8_t* input, mpz_t output) {  
    mpz_t inputnum;
    mpz_init(inputnum);
    for (uint8_t i = 0; i < 16; i++) {
        mpz_t byte;
        mpz_init(byte);
        mpz_set_ui(byte, input[i]);
        mpz_mul_2exp(byte, byte, (15-i) << 3);

        mpz_add(inputnum, inputnum, byte);

        mpz_clear(byte);
    }
    mpz_powm_sec(output, inputnum, e, n);
}

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

void sendaeskey(int conn_fd, mpz_t encrypted_data, mpz_t d, mpz_t n) {
    uint8_t buffer[128];
    memset(buffer, 0, 128);
    mpztobytearray(buffer, encrypted_data);
    send(conn_fd, buffer, 128, 0);
    memset(buffer, 0, 128);
    mpztobytearray(buffer, d);
    send(conn_fd, buffer, 128, 0);
    memset(buffer, 0, 128);
    mpztobytearray(buffer, n);
    send(conn_fd, buffer, 128, 0);
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

    // clock_t start, end;
    // start = clock();

    mpz_t d, e, n;
    mpz_inits(d, e, n, NULL);
    generatersakeypair(d, e, n);
    
    uint8_t key[16];
    srand(time(NULL));
    generateaeskey(key);
    uint8_t decrypted_data[16];
    mpz_t encrypted_data;
    mpz_init(encrypted_data);
    rsaencrypt(e, n, key, encrypted_data);
    sendaeskey(conn_fd, encrypted_data, d, n);
    mpz_clears(encrypted_data, d, e, n, NULL);

    senddata(conn_fd, argv[1], key);

    // end = clock();
    // double seconds = ((double)(end-start)) / CLOCKS_PER_SEC;
    // printf("%lf seconds.\n", seconds);

    close(conn_fd);
    close(sock_fd);
}