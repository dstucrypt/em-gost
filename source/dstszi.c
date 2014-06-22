#include "string.h"
#include "stdio.h"
#include "gost89.h"
#include "gosthash.h"
#include "sbox.h"
#include "util.h"
#include "dstszi.h"

static byte WRAP_IV[] = {
    0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05
};

int gost_kdf(const byte zz[ZZ_SIZE], const byte *shared, size_t shared_len, byte *ret) {
 
    int err;
    byte hash[32];
    byte counter[] = { 0, 0, 0, 1 };

    gost_hash_ctx hash_ctx;
    gost_subst_block sbox;

    unpack_sbox(default_sbox, &sbox);
    err = init_gost_hash_ctx(&hash_ctx, &sbox);

    err &= hash_block(&hash_ctx, zz, ZZ_SIZE);
    err &= hash_block(&hash_ctx, counter, 4);
    err &= hash_block(&hash_ctx, shared, shared_len);
    err &= finish_hash(&hash_ctx, hash);

    if(err != 1) {
        err = -1;
        goto out;
    }

    err = 0;

    memcpy(ret, hash, KEK_SIZE);

out:
    done_gost_hash_ctx(&hash_ctx);
    return err;
};

int gost_key_wrap(const byte cek[CEK_SIZE], const byte kek[KEK_SIZE], const byte iv[IV_SIZE], byte *ret) {
    int err, idx;
    gost_ctx ctx;
    gost_subst_block sbox;
    byte icv[4], cekicv[40], temp1[40], temp2[44], temp3[48], result[48];

    unpack_sbox(default_sbox, &sbox);
    gost_init(&ctx, &sbox);

    gost_key(&ctx, kek);
    err = gost_mac(&ctx, MAC_BITS, cek, CEK_SIZE, icv);
    if(err != 1) {
        fprintf(stderr, "failed to compute mac %d\n", err);
        return -2;
    }

    memset(cekicv, 0, sizeof(cekicv));
    memcpy(cekicv, cek, CEK_SIZE);
    memcpy(&cekicv[32], icv, sizeof(icv));

    gost_enc_cfb(&ctx, iv, cekicv, temp1, 5);

    memcpy(temp2, iv, IV_SIZE);
    memcpy(&temp2[8], temp1, sizeof(temp1) - 4);

    for(idx=0; idx < sizeof(temp3); idx++) {
        temp3[idx] = temp2[sizeof(temp2) - idx - 1];
    }

    gost_enc_cfb(&ctx, WRAP_IV, temp3, result, 6);

    gost_destroy(&ctx);

    memcpy(ret, result, WCEK_SIZE);

    return 0;
};

int gost_key_unwrap(const byte wcek[WCEK_SIZE], const byte kek[KEK_SIZE], byte *ret) {
    int err, idx;
    gost_ctx ctx;
    gost_subst_block sbox;
    byte iv[IV_SIZE], icv[4], cekicv[40], temp1[40], temp2[44], temp3[48];
    byte icv_check[4], iv_check[IV_SIZE];

    unpack_sbox(default_sbox, &sbox);
    gost_init(&ctx, &sbox);

    gost_key(&ctx, kek);
    gost_dec_cfb(&ctx, WRAP_IV, wcek, temp3, 6);

    for(idx=0; idx < sizeof(temp2); idx++) {
        temp2[idx] = temp3[sizeof(temp2) - idx - 1];
    }

    memcpy(iv, temp2, sizeof(iv));
    memcpy(temp1, temp2 + sizeof(iv), sizeof(temp2) - sizeof(iv));

    gost_dec_cfb(&ctx, iv, temp1, cekicv, 5);

    memcpy(icv, cekicv + CEK_SIZE, 4);

    err = gost_mac(&ctx, MAC_BITS, cekicv, CEK_SIZE, icv_check);

    err = icv[0] ^ icv_check[0];
    err |= icv[1] ^ icv_check[1];
    err |= icv[2] ^ icv_check[2];
    err |= icv[3] ^ icv_check[3];

    if(err != 0) {
        fprintf(stderr, "CEK keysum mismatch\n");
        err = -1;
        goto out;
    }

    memcpy(ret, cekicv, CEK_SIZE);

    err = 0;
out:
    gost_destroy(&ctx);

    return err;
}
