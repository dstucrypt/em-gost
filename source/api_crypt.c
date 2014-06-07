#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "gost89.h"
#include "gosthash.h"
#include "sbox.h"
#include "dstszi.h"

enum crypt_mode {
    GOST_CFB_ENC = 0,
    GOST_CFB_DEC = 1,
};

int gost_crypt(enum crypt_mode mode, const byte *buf, int buf_len, const byte cek[CEK_SIZE], const byte iv[IV_SIZE], byte *ret)
{
    int err, blocks;
    gost_ctx ctx;
    gost_subst_block sbox;
    unpack_sbox(default_sbox, &sbox);
    gost_init(&ctx, &sbox);

    if(!ret || !buf || !buf_len || !iv) {
        fprintf(stderr, "decrypt %p %p %d %p\n", ret, buf, buf_len, iv);
        err = -ENOMEM;
        goto out;
    }

    gost_key(&ctx, cek);

    blocks = (buf_len + 7) / 8;

    switch(mode) {
    case GOST_CFB_DEC:
        gost_dec_cfb(&ctx, iv, buf, ret, blocks);
        break;
    case GOST_CFB_ENC:
        gost_enc_cfb(&ctx, iv, buf, ret, blocks);
        break;
    default:
        err = -EINVAL;
    }

    err = 0;
out:
    gost_destroy(&ctx);

    return err;
}
