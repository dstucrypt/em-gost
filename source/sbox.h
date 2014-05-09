#ifndef UADSTU_SBOX_H
#define UADSTU_SBOX_H 1
void unpack_sbox(unsigned char* packed_sbox, gost_subst_block* unpacked_sbox);

extern unsigned char default_sbox[64];

#endif
