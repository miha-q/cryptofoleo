gcc -shared -fPIC src/all.c -o bin/libCryptoFoleo.so -lgmp -DDEVICE='"/dev/random"'
cp src/headers.h bin/CryptoFoleo.h
