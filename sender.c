#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>

// https://www.random.org/cgi-bin/randbyte?nbytes=16&format=h
#define KEY { 0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98 }

uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

uint32_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

void transpose(uint8_t* block) {
    uint8_t tmp = 0;
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = i+1; j < 4; j++) {
            tmp = block[(i << 2) + j];
            block[(i << 2) + j] = block[(j << 2) + i];
            block[(j << 2) + i] = tmp;
        }
    }
}

void keyexpansion(uint8_t* key, uint32_t* expanded_key) {
    for (uint8_t i = 0; i < 4; i++) {
        uint8_t four_i = i << 2;
        expanded_key[i] =
            (key[four_i] << 24)
            + (key[four_i + 1] << 16)
            + (key[four_i + 2] << 8)
            + key[four_i + 3];
    }

    for (uint8_t i = 4; i < 44; i++) {
        uint32_t xor = expanded_key[i-1];

        if (i % 4 == 0) {
            xor = (xor << 8) + (xor >> 24);

            uint8_t b0 = sbox[xor >> 24];
            uint8_t b1 = sbox[(xor >> 16) & 0xFF];
            uint8_t b2 = sbox[(xor >> 8) & 0xFF];
            uint8_t b3 = sbox[xor & 0xFF];

            xor = (b0 << 24) + (b1 << 16) + (b2 << 8) + b3;
            xor ^= rcon[(i >> 2)-1] << 24;
        }

        expanded_key[i] = expanded_key[i-4] ^ xor;
    }
}

void addroundkey(uint8_t* block, uint32_t* roundkey) {
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 4; j++) {
            block[(i << 2) + j] ^= (roundkey[j] >> ((3-i) << 3)) & 0xFF;
        }
    }
}

void subbytes(uint8_t* block) {
    for (uint8_t i = 0; i < 16; i++) {
        block[i] = sbox[block[i]];
    }
}

void shiftrows(uint8_t* block) {
    for (uint8_t i = 1; i < 4; i++) {
        uint32_t* row = (uint32_t*)block + (i << 2);
        *row = ( *row >> (i << 3) ) + ( *row << ((4-i) << 3) );
    }
}

uint8_t multiply(uint8_t b, uint8_t amount) {
    uint8_t original = b;
    uint8_t overflow = original >> 7;
    b <<= 1;
    if (overflow) b ^= 0x1B;
    if (amount == 3) b ^= original;
    return b;
}

void mixcolumns(uint8_t* block) {
    for (uint8_t i = 0; i < 4; i++) {
        uint8_t col[4] = { block[i], block[4+i], block[8+i], block[12+i] };
        block[i] = multiply(col[0], 2) ^ multiply(col[1], 3) ^ col[2] ^ col[3];
        block[4+i] = col[0] ^ multiply(col[1], 2) ^ multiply(col[2], 3) ^ col[3];
        block[8+i] = col[0] ^ col[1] ^ multiply(col[2], 2) ^ multiply(col[3], 3);
        block[12+i] = multiply(col[0], 3) ^ col[1] ^ col[2] ^ multiply(col[3], 2);
    }
}

void aesencrypt(uint8_t* block) {
    uint8_t key[16] = KEY;
    uint32_t expanded_key[44];
    memset(expanded_key, 0, 44*sizeof(uint32_t));

    keyexpansion(key, expanded_key);

    transpose(block);

    addroundkey(block, expanded_key);

    for (uint8_t round = 1; round <= 10; round++) {
        subbytes(block);
        shiftrows(block);
        if (round != 10) mixcolumns(block);
        addroundkey(block, expanded_key + (round << 2));
    }
    
    transpose(block);
}

int senddata(int conn_fd, char* filename) {
    FILE* f = fopen(filename, "rb");
    if (f == NULL) {
        printf("Cannot open file.\n");
        exit(1);
    }
    uint8_t buffer[16];
    memset(buffer, 0, 16);
    size_t len;
    while ((len = fread(buffer, sizeof(uint8_t), 16, f)) > 0) {
        aesencrypt(buffer);
        send(conn_fd, buffer, 16, 0);
        memset(buffer, 0, 16);
    }
    fclose(f);
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

    senddata(conn_fd, argv[1]);

    close(conn_fd);
    close(sock_fd);
}