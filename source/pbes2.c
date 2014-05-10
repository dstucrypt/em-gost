#include <stdio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include "string.h"
#include "gost89.h"
#include "gosthash.h"
#include "sbox.h"
#include "util.h"

int pbes2_detect(int input_fd) {
    int err;
    byte oid[9];
    byte oid_bes2[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d };

    lseek(input_fd, 9, SEEK_SET);
    err = read(input_fd, oid, 9);
    err = memcmp(oid_bes2, oid, 9);

    return err;
}

int pbes2_convert_password(const byte *pw, int pw_len, const byte *salt, int salt_len, int cycles, byte *key)
{
    int err;
    uint32_t i = 1, ins;
    byte hash[32], pw_pad36[32], pw_pad5C[32], pw_hash[32];

    gost_hash_ctx hash_ctx;
    gost_subst_block sbox;

    unpack_sbox(default_sbox, &sbox);
    err = init_gost_hash_ctx(&hash_ctx, &sbox);

    ins = ntohl(i);

    int k = 0;
    memset(pw_pad36, 0x36, 32);
    for(k=0; k < pw_len; k++) {
        pw_pad36[k] = pw[k] ^ 0x36;
    }
    k = 0;
    memset(pw_pad5C, 0x5C, 32);
    for(k=0; k < pw_len; k++) {
        pw_pad5C[k] = pw[k] ^ 0x5C;
    }

    err = hash_block(&hash_ctx, pw_pad36, 32);
    err &= hash_block(&hash_ctx, salt, salt_len);
    err &= hash_block(&hash_ctx, (byte*)&ins, 4);
    err &= finish_hash(&hash_ctx, hash);

    start_hash(&hash_ctx);
    err &= hash_block(&hash_ctx, pw_pad5C, 32);
    err &= hash_block(&hash_ctx, hash, 32);
    err &= finish_hash(&hash_ctx, hash);

    if(err != 1) {
        fprintf(stderr, "hash error %d\n", err);
        err = -1;
        goto err;
    }
    memcpy(key, hash, 32);

    for(int j = 1; j < cycles; j++) {
        start_hash(&hash_ctx);
        err = hash_block(&hash_ctx, pw_pad36, 32);
        err &= hash_block(&hash_ctx, hash, 32);
        err &= finish_hash(&hash_ctx, hash);

        start_hash(&hash_ctx);
        err &= hash_block(&hash_ctx, pw_pad5C, 32);
        err &= hash_block(&hash_ctx, hash, 32);
        err &= finish_hash(&hash_ctx, hash);

        if(err != 1) {
            fprintf(stderr, "hash error in loop %d\n", err);
            err = -1;
            goto err;
        }

        for(int ixor = 0; ixor < 32; ixor++) {
            key[ixor] ^= hash[ixor];
        }

    }

err:
    return err;
}

int pbes2_decode_file(int input_fd, const byte *pw, int pw_len, byte *clear) {
    int err;
    short iter;
    byte *salt, key[32];
    lseek(input_fd, 38, SEEK_SET);
    salt = malloc(32);
    err = read(input_fd, salt, 32);
    if(err != 32) {
        return -1;
    }

    lseek(input_fd, 72, SEEK_SET);
    err = read(input_fd, &iter, 2);
    if(err != 2) {
        return -1;
    }
    iter = ntohs(iter);
    err = pbes2_convert_password(pw, pw_len, salt, 32, iter, key);

    return -1;
}

