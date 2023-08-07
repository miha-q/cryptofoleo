gcc -shared -fPIC src/all.c -o bin/libFoleoCrypto.so -lgmp -DDEVICE='"/dev/random"'
cp src/headers.h bin/foleo-crypto.h
