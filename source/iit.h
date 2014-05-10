#ifndef UADSTU_IIT_H
#define UADSTU_IIT_H 1
int iit_decode_file(int input_fd, const byte *pw, int pw_len, byte *clear);
int iit_detect(int input_fd);
#endif

