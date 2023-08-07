#include <stdint.h>
#include <gmp.h>

uint8_t* chacha20(uint8_t[32], uint8_t[12], uint32_t, uint64_t);
uint8_t* chacha20_poly1305(uint8_t[32], uint8_t[12], uint8_t*, uint64_t);
uint8_t* dhke(uint8_t*, uint8_t*);
uint8_t* dhke_prf(uint32_t, uint8_t*, uint32_t, uint8_t*, uint32_t, uint8_t*, uint32_t);
uint8_t* poly1305(uint8_t*, uint8_t*, uint8_t*, uint32_t);
uint8_t* prigen(int);
typedef struct
{
    mpz_t n, k;
    uint16_t bitWidth;
} rsakey_t;
rsakey_t rsa_public(uint8_t*, uint16_t, uint8_t*, uint16_t, uint8_t*, uint16_t);
rsakey_t rsa_private(uint8_t*, uint16_t, uint8_t*, uint16_t, uint8_t*, uint16_t);
rsakey_t rsa_open(uint8_t*, uint16_t, uint8_t*, uint16_t);
void rsa_free(rsakey_t);
uint8_t* rsa_encrypt(rsakey_t, uint8_t, uint8_t*, uint16_t);
uint8_t* rsa_decrypt(rsakey_t, uint8_t, uint8_t*, uint16_t*);
uint8_t* sha256(uint8_t*, uint32_t);
