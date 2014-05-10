#ifndef UADSTU_PBES2_H
#define UADSTU_PBES2_H 1
int pbes2_detect(int input_fd);
int pbes2_decode_file(int input_fd, const byte *pw, int pw_len, byte *clear);
#endif

