# CryptoFoleo
A library with some basic cryptography for C and Haskell. 

Generate a pseudorandom number mask from ChaCha20 cipher. The first parameter is the key, the second is the nonce, the third is the starting block number, and the last is the number of bytes you want to generate. If you are using this in conjunction with Poly1305, then use a starting block of 1 and not 0. 

uint8_t* chacha20(uint8_t[32], uint8_t[12], uint32_t, uint64_t);

Generates a Poly1305 message authentication code. The first two parameters are again the key and the nonce for the ChaCha20 cipher, the second is the pointer to the message to be authenticated and the last is the length of the message.

uint8_t* chacha20_poly1305(uint8_t[32], uint8_t[12], uint8_t*, uint64_t);

Performs a Diffie-Hellman key exchange using the 4096-bit prime ID#16 located in RFC#3526. The two parameters are "private" and "public" where "private" refers to the secret randomly generated numbers and the "public" refers to the computed numbers that are shared across the network. If the function is called with both options as NULL, then it will return a randomly generated "private" value that is 512 bytes in size. If that private value is then passed into the first parameter with the second parameter public left as NULL, then it will return the 512 public bytes that are meant to be shared over the network. If the private value is passed into the first parameter and the public value received other the network is passed into the second parameter, it will then compute the 512 byte shared secret.

uint8_t* dhke(uint8_t*, uint8_t*);


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

uint8_t* dhke_prf(uint32_t, uint8_t*, uint32_t, uint8_t*, uint32_t, uint8_t*, uint32_t);
uint8_t* poly1305(uint8_t*, uint8_t*, uint8_t*, uint32_t);
uint8_t* prigen(int);
rsakey_t rsa_public(uint8_t*, uint16_t, uint8_t*, uint16_t, uint8_t*, uint16_t);
rsakey_t rsa_private(uint8_t*, uint16_t, uint8_t*, uint16_t, uint8_t*, uint16_t);
rsakey_t rsa_open(uint8_t*, uint16_t, uint8_t*, uint16_t);
void rsa_free(rsakey_t);
uint8_t* rsa_encrypt(rsakey_t, uint8_t, uint8_t*, uint16_t);
uint8_t* rsa_decrypt(rsakey_t, uint8_t, uint8_t*, uint16_t*);
uint8_t* sha256(uint8_t*, uint32_t);
