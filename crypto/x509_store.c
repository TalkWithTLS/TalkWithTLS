#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"

#define CHAIN1_CAFILE1 "../certs/ECC_Prime256_Certs/rootcert.pem"
#define CHAIN1_CERT_FILE "../certs/ECC_Prime256_Certs/serv_cert.pem"
#define CHAIN1_KEY_FILE "../certs/ECC_Prime256_Certs/serv_cert.pem"

#define CHAIN2_CAFILE1 "../certs/ECC_Prime256_Certs/rootcert.pem"
#define CHAIN1_CERT_FILE "../certs/ECC_Prime256_Certs/serv_cert.pem"
#define CHAIN1_KEY_FILE "../certs/ECC_Prime256_Certs/serv_cert.pem"

int main()
{
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_BUILT_ON));
    if (tls12_client()) {
        printf("TLS12 client connection failed\n");
    }
}
