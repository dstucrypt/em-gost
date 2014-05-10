#include "gost89.h"
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include "string.h"

int pbes2_detect(int input_fd) {
    int err;
    byte oid[9];
    byte oid_bes2[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d };

    lseek(input_fd, 9, SEEK_SET);
    err = read(input_fd, oid, 9);
    err = memcmp(oid_bes2, oid, 9);

    return err;
}

int pbes2_decode_file(int input_fd, const byte *pw, int pw_len, byte *clear) {
    return -1;
}

