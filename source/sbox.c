#include "gost89.h"

unsigned char default_sbox[64] =
    {
    0xa9, 0xd6, 0xeb, 0x45, 0xf1, 0x3c, 0x70, 0x82,
    0x80, 0xc4, 0x96, 0x7b, 0x23, 0x1f, 0x5e, 0xad,
    0xf6, 0x58, 0xeb, 0xa4, 0xc0, 0x37, 0x29, 0x1d,
    0x38, 0xd9, 0x6b, 0xf0, 0x25, 0xca, 0x4e, 0x17,
    0xf8, 0xe9, 0x72, 0x0d, 0xc6, 0x15, 0xb4, 0x3a,
    0x28, 0x97, 0x5f, 0x0b, 0xc1, 0xde, 0xa3, 0x64,
    0x38, 0xb5, 0x64, 0xea, 0x2c, 0x17, 0x9f, 0xd0,
    0x12, 0x3e, 0x6d, 0xb8, 0xfa, 0xc5, 0x79, 0x04
    };

void unpack_sbox(unsigned char* packed_sbox, gost_subst_block* unpacked_sbox)
{
    int i;
    for (i = 0; i < 8; i++)
	{
	unpacked_sbox->k1[2 * i] = 0x0f & (packed_sbox[i] >> 4);
	unpacked_sbox->k1[(2 * i) + 1] = 0x0f & packed_sbox[i];

	unpacked_sbox->k2[2 * i] = 0x0f & (packed_sbox[i + 8] >> 4);
	unpacked_sbox->k2[(2 * i) + 1] = 0x0f & packed_sbox[i + 8];

	unpacked_sbox->k3[2 * i] = 0x0f & (packed_sbox[i + 16] >> 4);
	unpacked_sbox->k3[(2 * i) + 1] = 0x0f & packed_sbox[i + 16];

	unpacked_sbox->k4[2 * i] = 0x0f & (packed_sbox[i + 24] >> 4);
	unpacked_sbox->k4[(2 * i) + 1] = 0x0f & packed_sbox[i + 24];

	unpacked_sbox->k5[2 * i] = 0x0f & (packed_sbox[i + 32] >> 4);
	unpacked_sbox->k5[(2 * i) + 1] = 0x0f & packed_sbox[i + 32];

	unpacked_sbox->k6[2 * i] = 0x0f & (packed_sbox[i + 40] >> 4);
	unpacked_sbox->k6[(2 * i) + 1] = 0x0f & packed_sbox[i + 40];

	unpacked_sbox->k7[2 * i] = 0x0f & (packed_sbox[i + 48] >> 4);
	unpacked_sbox->k7[(2 * i) + 1] = 0x0f & packed_sbox[i + 48];

	unpacked_sbox->k8[2 * i] = 0x0f & (packed_sbox[i + 56] >> 4);
	unpacked_sbox->k8[(2 * i) + 1] = 0x0f & packed_sbox[i + 56];
	}
}
