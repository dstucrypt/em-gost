#include "string.h"
#include "gost89.h"
#include "gosthash.h"
#include "sbox.h"

int compute_hash(const byte *buf, int buf_len, byte ret[32])
{
    int err = -1;

    gost_hash_ctx hash_ctx;
    gost_subst_block sbox;
    unpack_sbox(default_sbox, &sbox);
    byte hash[32];

    memset(&hash_ctx, 0, sizeof(hash_ctx));

    err = init_gost_hash_ctx(&hash_ctx, &sbox);
    if(err != 1) {
        return -1;
    }

    err = hash_block(&hash_ctx, buf, buf_len);
    if(err != 1) {
        err = -1;
        goto exit;
    }

    err = finish_hash(&hash_ctx, ret);
    if(err != 1) {
        err = -1;
        goto exit;
    }
    err = 0;

exit:
    done_gost_hash_ctx(&hash_ctx);
    return err;

}

