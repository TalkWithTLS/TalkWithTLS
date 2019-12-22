#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define EC256_CERT "./certs/ECC_Prime256_Certs/serv_cert.pem"
#define EC256_PRIV "./certs/ECC_Prime256_Certs/serv_key_unencrypted.pem"

#define ED25519_CERT "certs/ED25519/rootcert.pem"
#define ED25519_PRIV "certs/ED25519/rootkey.pem"

#define MAX_SIGN_SIZE 256

BIO *convert_file_2_bio(const char *file_name)
{
    BIO *bio_file;

    if ((bio_file = BIO_new(BIO_s_file())) == NULL) {
        printf("BIO new failed\n");
        goto err;
    }
    if (BIO_read_filename(bio_file, file_name) <=0) {
        printf("BIO read failed\n");
        goto err;
    }
    return bio_file;
err:
    BIO_free(bio_file);
    return NULL;
}

EVP_PKEY *get_pub_key(const char *pub_file)
{
    EVP_PKEY *pub_key = NULL;
    X509 *cert = NULL;
    BIO *bio_file;

    if ((bio_file = convert_file_2_bio(pub_file)) == NULL)
        goto err;

    if ((cert = PEM_read_bio_X509(bio_file, NULL, NULL, NULL)) == NULL) {
        printf("Cert read failed\n");
        goto err;
    }

    if ((pub_key = X509_get_pubkey(cert)) == NULL) {
        printf("Get pub key failed\n");
        goto err;
    }
    printf("Decoded cert[%s] successfully\n", pub_file);
err:
    BIO_free(bio_file);
    X509_free(cert);
    return pub_key;
}

EVP_PKEY *get_priv_key(const char *priv_file)
{
    EVP_PKEY *priv_key = NULL;
    BIO *bio_file;

    if ((bio_file = convert_file_2_bio(priv_file)) == NULL)
        goto err;
    if ((priv_key = PEM_read_bio_PrivateKey(bio_file, NULL, NULL, NULL)) == NULL) {
        printf("Decode priv key failed\n");
        goto err;
    }
    printf("Decoded priv key[%s] successfully\n", priv_file);
err:
    BIO_free(bio_file);
    return priv_key;
}

int do_sign_verify(int alg_nid, const char *cert_file, const char *priv_file, int secs)
{
    EVP_MD_CTX *ed_sign_ctx = NULL, *ed_veri_ctx = NULL;
    EVP_PKEY *ed_pub_key;
    EVP_PKEY *ed_priv_key = NULL;
    int ret_val = -1;
    uint8_t sign[MAX_SIGN_SIZE] = {0};
    size_t sign_len;
    char data[] = "abcdefghijabcdefghij";
    long finish_time;
    uint32_t count;

    if ((ed_pub_key = get_pub_key(cert_file)) == NULL)
        goto err;
    if ((ed_priv_key = get_priv_key(priv_file)) == NULL)
        goto err;

    if ((ed_sign_ctx = EVP_MD_CTX_new()) == NULL
            || EVP_DigestSignInit(ed_sign_ctx, NULL, NULL, NULL, ed_priv_key) != 1) {
        printf("MD Sign ctx init failed\n");
        goto err;
    }

    if ((ed_veri_ctx = EVP_MD_CTX_new()) == NULL
            || EVP_DigestVerifyInit(ed_veri_ctx, NULL, NULL, NULL, ed_pub_key) != 1) {
        printf("MD Verify Ctx init failed\n");
        goto err;
    }

    finish_time = time(NULL) + secs;
    while (1) {
        sign_len = sizeof(sign);
        if (finish_time < time(NULL)) {
            break;
        }
        if (EVP_DigestSign(ed_sign_ctx, sign, &sign_len, (uint8_t *)data, strlen(data)) != 1) {
            printf("ED Sign failed\n");
            goto err;
        }

        if (EVP_DigestVerify(ed_veri_ctx, sign, sign_len, (uint8_t *)data, strlen(data)) != 1) {
            printf("MD Verify failed\n");
            goto err;
        }
        printf("*");
        count++;
    }
    printf("\n%s Sign/Verify of data %zu bytes performed %u operations in %d secs\n",
            OBJ_nid2sn(alg_nid), sizeof(data), count, secs);
    printf("%s Sign/Verify of data %zu bytes performed %u operations/secs\n",
            OBJ_nid2sn(alg_nid), sizeof(data), count/secs);
    ret_val = 0;
err:
    EVP_PKEY_free(ed_pub_key);
    EVP_PKEY_free(ed_priv_key);
    EVP_MD_CTX_free(ed_sign_ctx);
    EVP_MD_CTX_free(ed_veri_ctx);
    return ret_val;
}

#define RAND_SIZE 224
int do_rand(int secs)
{
    long finish_time;
    uint8_t data[RAND_SIZE] = {0};
    uint32_t count;
    int ret;

    finish_time = time(NULL) + secs;
    while (1) {
        if (finish_time < time(NULL)) {
            break;
        }

        if ((ret = RAND_priv_bytes(data, sizeof(data))) != 1) {
            printf("RAND_priv_bytes failed\n");
            goto err;
        }
        printf("*");
        count++;
    }
    printf("\nRand of data %zu bytes performed %u operations in %d secs\n",
            sizeof(data), count, secs);
    printf("Rand of data %zu bytes performed %u operations/secs\n",
            sizeof(data), count/secs);
    printf("Rand generation performance is %f MB/secs\n",
            (((float)(sizeof(data) * count)) / secs) / (1024 * 1024));
    return 0;
err:
    return -1;
}

#define ENC_DATA_SIZE 256
#define ENC_KEY_SIZE 16
int do_enc_dec(int secs, int nid)
{
    long finish_time;
    uint8_t data[ENC_DATA_SIZE] = {0};
    uint8_t out[ENC_DATA_SIZE] = {0};
    uint8_t key[ENC_KEY_SIZE] = {0};
    const EVP_CIPHER *ciph;
    EVP_CIPHER_CTX *ciph_ctx = NULL;
    uint32_t count;
    int ret_val = -1;

    if ((ciph = EVP_get_cipherbynid(nid)) == NULL) {
        printf("Get cipher by nid failed\n");
        goto err;
    }

    if ((ciph_ctx = EVP_CIPHER_CTX_new()) == NULL
            || EVP_EncryptInit_ex(ciph_ctx, ciph, NULL, key, NULL) != 1) {
        printf("Cipher ctx init failed\n");
        goto err;
    }

    memset(data, 'a', sizeof(data));
    finish_time = time(NULL) + secs;
    while (1) {
        if (finish_time < time(NULL)) {
            break;
        }
        if (EVP_Cipher(ciph_ctx, out, data, sizeof(data)) != 1) {
            printf("EVP Cipher failed\n");
            goto err;
        }
        //TODO Need to add decrpytion and memcmp also
        printf("*");
        count++;
    }
    printf("\nEnc/Dec of data %zu bytes performed %u operations in %d secs\n",
            sizeof(data), count, secs);
    printf("Enc/Dec of data %zu bytes performed %u operations/secs\n",
            sizeof(data), count/secs);
    printf("Enc/Dec performance is %f MB/secs\n",
            (((float)(sizeof(data) * count)) / secs) / (1024 * 1024));
    ret_val = 0;
err:
    EVP_CIPHER_CTX_free(ciph_ctx);
    return ret_val;
}

int main(int argc, char *argv[])
{
    int secs = 10;
    //return do_sign_verify(NID_ED25519, ED25519_CERT, ED25519_PRIV, secs);
    return do_sign_verify(NID_X9_62_prime256v1, EC256_CERT, EC256_PRIV, secs);
    //return do_rand(secs);
    //return do_enc_dec(secs, NID_aes_128_ctr);
}
