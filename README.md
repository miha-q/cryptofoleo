# CryptoFoleo
A library with some basic cryptography for C and Haskell. 

    uint8_t* chacha20(uint8_t[32], uint8_t[12], uint32_t, uint64_t);

Generate a pseudorandom number mask from ChaCha20 cipher. The first parameter is the key, the second is the nonce, the third is the starting block number, and the last is the number of bytes you want to generate. If you are using this in conjunction with Poly1305, then you MUST use a starting block greater than zero.

    uint8_t* poly1305(uint8_t*, uint8_t*, uint8_t*, uint32_t);    

Generate a Poly1305 hash where the first two parameters are 16-byte starting states (r, s), the third is a pointer to the data to hash, and the last is the length of that data. A Poly1305 hash is always 16 bytes. 

    uint8_t* chacha20_poly1305(uint8_t[32], uint8_t[12], uint8_t*, uint64_t);    

Generates a Poly1305 message authentication code. The first two parameters are again the key and the nonce for the ChaCha20 cipher, the second is the pointer to the message to be authenticated and the last is the length of the message. This code is again 16 bytes.

    uint8_t* dhke(uint8_t*, uint8_t*);    

Performs a Diffie-Hellman key exchange using the 4096-bit prime ID#16 located in RFC#3526. The two parameters are "private" and "public" where "private" refers to the initial randomly generated numbers and "public" refers to the computed numbers that are shared across the network. If the function is called with both options as NULL, then it will return a randomly generated "private" value that is 512 bytes in size. If that private value is then passed into the first parameter with the public parameter, the second parameter, left as NULL, then it will return the 512 public bytes that are meant to be shared over the network. If the private value is passed into the first parameter and the public value received other the network is passed into the second parameter, it will then compute the 512 byte shared secret. This one function can therefore handle the entire key exchange process. 

    uint8_t* dhke_prf(uint32_t, uint8_t*, uint32_t, uint8_t*, uint32_t, uint8_t*, uint32_t);    

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

    uint8_t* prigen(uint16_t);    

Generates a random prime number. The parameter is the byte-width of the prime number. For example, if you want to generate random 1024-bit RSA keys, then you can call this twice passing in the number 128.

    rsakey_t rsa_public(uint8_t*, uint16_t, uint8_t*, uint16_t, uint8_t*, uint16_t);    

This takes three parameters: p, q, and e, and from them calculates the RSA public key. The reason there are six parameters is because after each key buffer is another parameter specifying the size of that buffer in bytes.

    rsakey_t rsa_private(uint8_t*, uint16_t, uint8_t*, uint16_t, uint8_t*, uint16_t);    

Same as above except it calculates the RSA private key.

    rsakey_t rsa_import(uint8_t*, uint16_t, uint8_t*, uint16_t);    

Imports an RSA key from a buffer. This expects you to either pass in d and n, or e and n, depending on whether or not it is a private or public key.

``uint8_t* rsa_export(rsakey_t, uint8_t, uint16_t*);``

Export an RSA key. The second parameter specifies which key you want to export. For public keys, valid options are the byte 'e' or the byte 'n'. For private keys, valid options are the byte 'd' or the byte 'n'. The last parameter will contain the size of the key in bytes, and the function returns a pointer to that key.

    void rsa_free(rsakey_t);    

Free the memory associated with an RSA key.

    uint8_t* rsa_encrypt(rsakey_t, uint8_t, uint8_t*, uint16_t);    

Encrypts some data using an RSA key. This only encrypts a single block which is why the last parameter, which specifies the size of the data you wish to encrypt, is only a 16-bit integer. If you want to encrypt many blocks of data, you will need to break your data up into blocks manually and call this for each block. The third parameter points to the buffer of data you want to encrypt. 

The second parameter is the type of padding to be used during encryption. Current supported options are RSA_ENCRYPTION which applies PKCS#1 v1.5 encryption padding, RSA_SIGNATURE which applies PKCS#1 v1.5 signature padding, and RSA_OAEP which applies optimal asymmetric encryption padding. You can also pass RSA_NONE into it for no padding at all.

    uint8_t* rsa_decrypt(rsakey_t, uint8_t, uint8_t*, uint16_t*);    

This will both decrypt and "de-pad" RSA ciphertext blocks. Since the size of the message could be smaller than the maximum size that could fit into the block, it also will return the message size after decryption as the last parameter. Like with encryption, you can also specify the padding type. If the padding types do not match up from what was encrypted, it will fail to decrypt, returning a NULL value.

    uint8_t* sha256(uint8_t*, uint32_t);    

Computes a SHA-256 hash with the two parameters being a pointer to the data and the size of the data to be hashed.
