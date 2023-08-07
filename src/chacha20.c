#ifndef __CHACHA20__
#define __CHACHA20__
#include <stdio.h>
#include <stdint.h>
#include "poly1305.c"

static uint32_t chacha20_lr(uint32_t a, uint8_t b)
{
	return (a << b) | (a >> (32 - b));
}

static void chacha20_QR(uint32_t *cc, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	cc[a] += cc[b]; cc[d] ^= cc[a]; cc[d] = chacha20_lr(cc[d], 16);
	cc[c] += cc[d]; cc[b] ^= cc[c]; cc[b] = chacha20_lr(cc[b], 12);
	cc[a] += cc[b]; cc[d] ^= cc[a]; cc[d] = chacha20_lr(cc[d], 8);
	cc[c] += cc[d]; cc[b] ^= cc[c]; cc[b] = chacha20_lr(cc[b], 7);
}

static void chacha20_DR(uint32_t *cc)
{
	chacha20_QR(cc, 0, 4,  8, 12);
	chacha20_QR(cc, 1, 5,  9, 13);
	chacha20_QR(cc, 2, 6, 10, 14);
	chacha20_QR(cc, 3, 7, 11, 15);
	chacha20_QR(cc, 0, 5, 10, 15);
	chacha20_QR(cc, 1, 6, 11, 12);
	chacha20_QR(cc, 2, 7,  8, 13);
	chacha20_QR(cc, 3, 4,  9, 14);
}

static void chacha20_CB(uint32_t *cc)
{
	uint8_t i;
	uint32_t x[16];
	for (i = 0; i < 16; i++)
	{
		x[i] = cc[i];
	}
	for (i = 0; i < 10; i++)
	{
		chacha20_DR(cc);
	}
	for (i = 0; i < 16; i++)
	{
		cc[i] += x[i];
	}
}

static void chacha20_S(uint32_t *cc, uint8_t *cs)
{
	for (uint8_t i = 0; i < 16; i++)
	{
		cs[4 * i] = (cc[i] & 0xFF);
		cs[4 * i + 1] = ((cc[i] >> 8) & 0xFF);
		cs[4 * i + 2] = ((cc[i] >> 16) & 0xFF);
		cs[4 * i + 3] = ((cc[i] >> 24) & 0xFF);
	}
}

static void chacha20_block(uint8_t key[32], uint8_t nonce[12], uint32_t block, uint8_t out[64])
{
	uint32_t cc[] =
	{
       0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,

	   key[0] | (key[1] << 8) | (key[2] << 16) | (key[3] << 24),
	   key[4] | (key[5] << 8) | (key[6] << 16) | (key[7] << 24),
	   key[8] | (key[9] << 8) | (key[10] << 16) | (key[11] << 24),
	   key[12] | (key[13] << 8) | (key[14] << 16) | (key[15] << 24),

	   key[16] | (key[17] << 8) | (key[18] << 16) | (key[19] << 24),
	   key[20] | (key[21] << 8) | (key[22] << 16) | (key[23] << 24),
	   key[24] | (key[25] << 8) | (key[26] << 16) | (key[27] << 24),
	   key[28] | (key[29] << 8) | (key[30] << 16) | (key[31] << 24),

       block,

	   nonce[0] | (nonce[1] << 8) | (nonce[2] << 16) | (nonce[3] << 24),
	   nonce[4] | (nonce[5] << 8) | (nonce[6] << 16) | (nonce[7] << 24),
	   nonce[8] | (nonce[9] << 8) | (nonce[10] << 16) | (nonce[11] << 24)
	};

	chacha20_CB(cc);
	chacha20_S(cc, out);
}

/*Don't use block #0 if you are using this in conjunction with poly1305*/
uint8_t* chacha20(uint8_t key[32], uint8_t nonce[12], uint32_t block, uint64_t count)
{
	if (count > (274877906944 - block * 64)) return NULL;
	uint8_t* ret = malloc(0);
	uint8_t ccblock[64];
	uint64_t size = 0;
	while (count > 64)
	{
		ret = realloc(ret, size + 64);
		chacha20_block(key, nonce, block++, ccblock);
		for (uint8_t i = 0; i < 64; i++) ret[size + i] = ccblock[i];
		size += 64;
		count -= 64;
	}
	if (count > 0)
	{
		ret = realloc(ret, size + count);
		chacha20_block(key, nonce, block, ccblock);
		for (uint8_t i = 0; i < count; i++) ret[size + i] = ccblock[i];
	}
	return ret;
}

//Calculates poly1305 for ciphertext encrypted with chacha20
uint8_t* chacha20_poly1305(uint8_t key[32], uint8_t nonce[12], uint8_t* cipherText, uint64_t lengthInBytes)
{
	uint8_t* keydata = chacha20(key, nonce, 0, 32);
	uint8_t r[16];
	uint8_t s[16];
	for (uint8_t i = 0; i < 16; i++)
	{
		r[i] = keydata[i];
		s[i] = keydata[i + 16];
	}
	free(keydata);
	return poly1305(r, s, cipherText, lengthInBytes);
}

#endif