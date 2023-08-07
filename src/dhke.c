#ifndef __DHKE__
#define __DHKE__
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmp.h>
#include "sha256.c"

/*
dhke(private, public)

Here, "private" refers to random numbers intended to be used in the key exchange
while "public" refers to the public information shared in the communication.
If both are NULL, then it will generate random private numbers and return those
as a buffer. If you then pass those into the function again as the private
parameter and leave public as NULL, it will generate the public value meant to
be shared. If you pass in your private value as the private parameter and the
public value you acquired from the other person as the public parameter, it will
return the shared secret.

dhke_prf(desiredBytes, secret, secretS, label, labelS, seed, seedS)

Because the key is 4096 bits long which may either be too much or too little
depending on your purposes, this library also offers as a way to convert the
output of the key exchange into any arbitrary number of bytes appropriate
for your purposes.

The "desired bytes" is the amount of bytes you want and the "secret" should
be the 4096 byte shared secret arrived at after the key exchange. Note that
the parameters that end with a capital S are just the length of bytes of
the buffer pointed to by the previous parameter.

The label should specify the kind of operation being done.

It is common to not use the Diffie-Hellman output directly but instead
transform it into another shared secret by first passing it into the PRF.
Since the PRF is effectively a pseudorandom number generator, if both sides
start with the same seed, they will still derive the same secret. In this
case, the label is specified as "master secret" without a null terminator.

This master secret is then used to derive further session keys to be used
later in the communication, and at that point PRF() is called again with
a different level "key expansion" again without the null terminator. Using
different labels for different operations makes sure you get a different
set of pseudorandom numbers per operations which both parties should agree
upon.

The seed helps increase the unpredictability of the PRF function by
introducing additional random numbers into the starting point of the PRF()
function. Since both parties need to produce the same numbers, this seed
will have to be shared publicly, typically as part of the same handshake
where they exchange their Diffie-Hellman numbers.

The PRF() function utilizes the SHA-256 hash, but in theory could be
modified to support any hash. However, SHA-256 is a pretty common industry
standard, so for simplification reasons, the PRF() here does not require
a hash as an input but just chooses SHA-256 with appropriate parameters
automagically.
*/


/*
    key exchange here is fixed to using a group from RFC#3526
*/
static uint8_t RFC3526ID16[] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
    0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
    0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
    0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D,
    0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
    0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
    0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
    0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D,
    0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7,
    0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
    0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
    0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
    0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64,
    0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C,
    0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
    0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
    0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
    0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01,
    0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
    0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26,
    0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C,
    0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
    0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8,
    0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9,
    0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
    0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D,
    0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2,
    0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
    0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF,
    0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C,
    0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
    0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1,
    0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F,
    0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x06, 0x31, 0x99,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static void dhke_store(mpz_t n, uint8_t* b, uint32_t s)
{
    for (uint32_t i = 0; i < s; i++)
    {
        b[s - (i + 1)] = mpz_get_ui(n);
        mpz_div_ui(n, n, 256);
    }
}

static void dhke_load(mpz_t n, uint8_t* b, uint32_t s)
{
    mpz_set_ui(n, 0);
    for (uint32_t i = 0; i < s; i++)
    {
        mpz_mul_ui(n, n, 256);
        mpz_add_ui(n, n, b[i]);
    }
}

/*
    pass in NULL for both to get a new private value
    pass in the private value with a null for public
        to return the public value to be shared
    pass in the private value and the public
        received to compute the final key
*/
uint8_t* dhke(uint8_t* private, uint8_t* public)
{
    mpz_t n, g, p;
    mpz_init(n);
    mpz_init(g);
    mpz_init(p);
    mpz_set_ui(g, 2);
    dhke_load(p, RFC3526ID16, 512);
    uint8_t* out = malloc(512);

    if (private == NULL && public == NULL)
    {
        FILE* f = fopen(DEVICE, "r");
        fread(out, 1, 512, f);
        fclose(f);
        out[0] = out[0] & 0b01111111;
    }
    else if (private != NULL && public == NULL)
    {
        dhke_load(n, private, 512);
        mpz_powm(n, g, n, p);
        dhke_store(n, out, 512);
    }
    else
    {
        mpz_t m;
        mpz_init(m);
        dhke_load(m, private, 512);
        dhke_load(n, public, 512);
        mpz_powm(n, n, m, p);
        dhke_store(n, out, 512);
        mpz_clear(m);
    }

    mpz_clear(n);
    mpz_clear(g);
    mpz_clear(p);
    return out;
}

//HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m))
static uint8_t* dhke_hmac
(
    uint8_t* (hash_func)(uint8_t*, uint32_t),
    uint32_t Hs, //hash size
    uint32_t Bs, //block size
    uint8_t* K,
    uint32_t Ks, //K size
    uint8_t* M,
    uint32_t Ms //M size
)
{
    uint8_t* tmp1;
    uint8_t* Kp; //K prime

    if (Ks <= Bs)
    {
        Kp = malloc(Bs);
        for (uint32_t i = 0; i < Bs; i++)
        {
            Kp[i] = i < Ks ? K[i] : 0;
        }
    }
    else
    {
        tmp1 = hash_func(K, Ks);
        Kp = malloc(Bs);
        for (uint32_t i = 0; i < Bs; i++)
        {
            Kp[i] = i < Hs ? tmp1[i] : 0;
        }
        free(tmp1);
    }
    
    //opad and ipad
    uint8_t opad[Bs];
    uint8_t ipad[Bs];
    for (uint32_t i = 0; i < Bs; i++)
    {
        opad[i] = 0x5C;
        ipad[i] = 0x36;
    }
    tmp1 = malloc(Bs + Ms);
    for (uint32_t i = 0; i < Bs + Ms; i++)
    {
        tmp1[i] = i < Bs ? Kp[i] ^ ipad[i] :  M[i - Bs];
    }
    uint8_t* tmp2 = hash_func(tmp1, Bs + Ms);
    free(tmp1);

    tmp1 = malloc(Bs + Hs);
    for (uint32_t i = 0; i < Bs + Hs; i++)
    {
        tmp1[i] = i < Bs ? Kp[i] ^ opad[i] : tmp2[i - Bs];
    }
    free(tmp2);
    free(Kp);

    tmp2 = hash_func(tmp1, Bs + Hs);
    free(tmp1);
    return tmp2;
    
}

//A(0) = seed
//A(i) = HMAC_hash(secret, A(i-1))
static uint8_t* dhke_hmac_A
(
    uint8_t iter, //iteration
    uint8_t* (hash_func)(uint8_t*, uint32_t),
    uint32_t Hs, //hash size
    uint32_t Bs, //block size
    uint8_t* secret,
    uint32_t secretS, //secret size
    uint8_t* seed,
    uint32_t seedS, //seed size
    uint32_t* returnSize
)
{
    uint8_t* out;
    if (iter == 0)
    {
        out = malloc(seedS);
        for (uint32_t i = 0; i < seedS; i++)
        {
            out[i] = seed[i];
        }
        *returnSize = seedS;
        return out;
    }
    uint32_t retSize;
    uint8_t* tmp = dhke_hmac_A(iter - 1, hash_func, Hs, Bs, secret, secretS, seed, seedS, &retSize);
    out = dhke_hmac(hash_func, Hs, Bs, secret, secretS, tmp, retSize);
    free(tmp);
    *returnSize = Hs;
    return out;
}

//PRF(secret, label, seed) = P_<hash>(secret, label + seed)
// = HMAC_hash(secret, A(i) + seed)
//We are using sha256, but this is coded in such a way
//  that we could extend it to other algorithms in the
//  future.
uint8_t* dhke_prf
(
    uint32_t desiredBytes,
    uint8_t* secret,
    uint32_t secretS,
    uint8_t* label,
    uint32_t labelS,
    uint8_t* seed,
    uint32_t seedS
)
{
    uint32_t Hs = 32; 
    uint32_t Bs = 64;
    uint32_t iter = 1;
    uint8_t* keystream = malloc(0);
    uint8_t* labelSeed = malloc(labelS + seedS);

    for (uint32_t i = 0; i < labelS + seedS; i++)
        labelSeed[i] = i < labelS ? label[i] : seed[i - labelS];
    
    while (desiredBytes != 0)
    {
        uint32_t tmp1S;
        uint8_t* tmp1 = dhke_hmac_A(iter, sha256, Hs, Bs, secret, secretS, labelSeed, labelS + seedS, &tmp1S);
        tmp1 = realloc(tmp1, tmp1S + labelS + seedS);
        for (uint32_t i = 0; i < labelS + seedS; i++)
            tmp1[i + tmp1S] = labelSeed[i];
        uint8_t* tmp2 = dhke_hmac(sha256, Hs, Bs, secret, secretS, tmp1, tmp1S + labelS + seedS);
        free(tmp1);
        if (desiredBytes >= Bs)
        {
            keystream = realloc(keystream, iter * Bs);
            for (uint32_t i = 0; i < Bs; i++)
                keystream[i + (iter - 1) * Bs] = tmp2[i];
            desiredBytes -= Bs;
        }
        else
        {
            keystream = realloc(keystream, (iter - 1) * Bs + desiredBytes);
            for (uint32_t i = 0; i < desiredBytes; i++)
                keystream[i + (iter - 1) * Bs] = tmp2[i];
            desiredBytes = 0;
        }
        free(tmp2);
        iter++;
    }
    free(labelSeed);
    return keystream;
}
#endif
