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

int convert_password(const byte* pw, int pw_len, byte* key) {
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

int decode_data(byte* data, int data_len, byte key[32], byte mac[4], byte* clear) {
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

    err = memcmp(mac, mac_check, 4);
    if(err != 0) {
        hexdump("Expected mac: ", mac, 4);
        hexdump("Got mac: ", mac_check, 4);
        fprintf(stderr, "Cant decode data: Invalid password.\n");
        return -3;
    }

    return err;
}

int main(int argc, char **argv) {
    int err, input_fd, out_fd, have;
    byte key[32], mac[4], mac_check[4];
    byte data[1024], clear[1024];

    if(argc < 2) {
        fprintf(stderr, "No password passed\n");
        return 1;
    }

    err = convert_password((byte*)argv[1], strlen(argv[1]), key);

    input_fd = open("key.dat", O_RDONLY);
    if(input_fd < 0) {
        fprintf(stderr, "failed to open data file\n");
        return 1;
    }

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
    close(input_fd);

    err = decode_data(data, have, key, mac, clear);

    out_fd = open("out.clear.c.test", O_WRONLY | O_CREAT | O_TRUNC);
    if(out_fd < 0) {
        fprintf(stderr, "cant open output file: %d\n", out_fd);
        return 1;
    }
    write(out_fd, clear, have);
    fprintf(stderr, "clear key written to output\n");
    close(out_fd);
}
