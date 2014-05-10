#include "stdio.h"
#include "string.h"
#include "gost89.h"
#include "util.h"
#include "sbox.h"
#include "iit.h"
#include "pbes2.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/stat.h>


enum format_t {
    FORMAT_ERR = -1,
    FORMAT_IIT,
    FORMAT_PBES2,
};

enum format_t detect_format(input_fd) {
    int err;

    err = iit_detect(input_fd);
    if(err == 0)
        return FORMAT_IIT;

    err = pbes2_detect(input_fd);
    if(err == 0)
        return FORMAT_PBES2;

    return FORMAT_ERR;
}

int main(int argc, char **argv) {
    int err, input_fd, out_fd, have;
    byte clear[1024];
    enum format_t fmt = FORMAT_ERR;

    if(argc < 2) {
        fprintf(stderr, "No password passed\n");
        return 1;
    }

    input_fd = open("key.dat", O_RDONLY);
    if(input_fd < 0) {
        fprintf(stderr, "failed to open data file\n");
        return 1;
    }

    fmt = detect_format(input_fd);
    switch(fmt) {
    case FORMAT_IIT:
        have = iit_decode_file(input_fd, (byte*)argv[1], strlen(argv[1]), clear);
        break;
    case FORMAT_PBES2:
        have = pbes2_decode_file(input_fd, (byte*)argv[1], strlen(argv[1]), clear);
        break;
    case FORMAT_ERR:
        err = -1;
        break;
    }

    close(input_fd);

    if(have < 0) {
        fprintf(stderr, "cant decode file: %d\n", err);
    }

    out_fd = open("out.clear.c.test", O_WRONLY | O_CREAT | O_TRUNC);
    if(out_fd < 0) {
        fprintf(stderr, "cant open output file: %d\n", out_fd);
        return 1;
    }
    fchmod(out_fd, S_IRUSR | S_IWUSR);
    write(out_fd, clear, have);
    fprintf(stderr, "clear key written to output\n");
    close(out_fd);
}
