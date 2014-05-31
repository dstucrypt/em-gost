#ifndef DSTSZI_H
#define DSTSZI_H 1

#define ZZ_SIZE 21
#define CEK_SIZE 32
#define KEK_SIZE 32
#define IV_SIZE 8
#define WCEK_SIZE 44
#define MAC_BITS 32

int gost_kdf(const byte zz[ZZ_SIZE], const byte *shared, size_t shared_len, byte *ret);
int gost_key_wrap(const byte cek[CEK_SIZE], const byte kek[KEK_SIZE], const byte iv[IV_SIZE], byte *ret);
int gost_key_unwrap(const byte wcek[WCEK_SIZE], const byte kek[KEK_SIZE], byte *ret);

#endif
