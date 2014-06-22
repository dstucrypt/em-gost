#include "stdio.h"
#include "string.h"
#include "gost89.h"
#include "gosthash.h"
#include "util.h"
#include "sbox.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

static byte oid_iit[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0x97, 0x46, 0x01, 0x01, 0x01, 0x02};

int iit_detect(int input_fd) {
    int err;
    byte oid[12];

    lseek(input_fd, 8, SEEK_SET);
    err = read(input_fd, oid, 12);
    err = memcmp(oid_iit, oid, 12);

    return err;
}

int iit_convert_password(const byte* pw, int pw_len, byte* key) {
    int err = -1;
    gost_hash_ctx hash_ctx;
    gost_subst_block sbox;
    unpack_sbox(default_sbox, &sbox);
    byte hash[32];

    memset(&hash_ctx, 0, sizeof(hash_ctx));

    if(pw == NULL || key == NULL) {
        fprintf(stderr, "no pw passed\n");
        return -1;
    }
 
    err = init_gost_hash_ctx(&hash_ctx, &sbox);
    if(err != 1) {
        return -1;
    }
    err = hash_block(&hash_ctx, pw, pw_len);
    if(err != 1) {
        err = -1;
        goto exit;
    }

    err = finish_hash(&hash_ctx, hash);

    if(err != 1) {
        err = -1;
        goto exit;
    }
    for (int i = 1; i < 10000; i++) {
        start_hash(&hash_ctx);
        err = hash_block(&hash_ctx, hash, 32);
        if(err != 1) {
            err = -1;
            goto exit;
        }

        err = finish_hash(&hash_ctx, hash);
        if(err != 1) {
            err = -1;
            goto exit;
        }
    }

    memcpy(key, hash, 32);

    err = 0;

exit:
    done_gost_hash_ctx(&hash_ctx);
    return err;
}

int iit_decode_data(byte* data, int data_len, byte key[32], byte mac[4], byte* clear) {
    int err;
    byte mac_check[4];
    gost_ctx ctx;
    gost_subst_block sbox;
    unpack_sbox(default_sbox, &sbox);

    err = -1;
    if(!data | !data_len | !key | !mac | !clear ) {
        fprintf(stderr, "broken args\n");
        return err;
    }

    memset(clear, 0, data_len);
    int blocks = (data_len + 7) / 8;
    gost_init(&ctx, &sbox);
    gost_key(&ctx, key);
    gost_dec(&ctx, data, clear, blocks);

    err = gost_mac(&ctx, 32, clear, data_len, mac_check);
    if(err != 1) {
        fprintf(stderr, "failed to compute mac (data %d): %d\n", data_len, err);
        return -2;
    }

    err = mac[0] ^ mac_check[0];
    err |= mac[1] ^ mac_check[1];
    err |= mac[2] ^ mac_check[2];
    err |= mac[3] ^ mac_check[3];

    if(err != 0) {
        hexdump("Expected mac: ", mac, 4);
        hexdump("Got mac: ", mac_check, 4);
        fprintf(stderr, "Cant decode data: Invalid password.\n");
        return -3;
    }

    return err;
}

int iit_decode_file(int input_fd, const byte *pw, int pw_len, byte *clear) {
    int err, have;
    byte key[32], mac[4], mac_check[4];
    byte data[1024];

    err = iit_convert_password(pw, pw_len, key);

    lseek(input_fd, 24, SEEK_SET);
    err = read(input_fd, mac, 4);
    if(err != 4) {
        fprintf(stderr, "failed to read input\n");
        return 1;
    }

    lseek(input_fd, 38, SEEK_SET);
    memset(data, 0, 1024);
    have = read(input_fd, data, 1024);
    if(have < 100) {
        fprintf(stderr, "dont have enough data: %d\n", have);
        return 1;
    }
    lseek(input_fd, 30, SEEK_SET);
    err = read(input_fd, data+have, 4);
    if(err != 4) {
        fprintf(stderr, "read error, dunno what to do %d\n", err);
    }

    err = iit_decode_data(data, have, key, mac, clear);
    if(err == 0)
        return have;
    return err;
}
