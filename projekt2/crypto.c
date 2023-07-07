#include <openssl/rsa.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <fcntl.h>
#include "error.h" 
#include "aes.h" 
#include "crypto.h"

#define AES_KEY_SIZE (128 / 8)
#define PADDING_SIZE (2048 / 8)

void padding_128bit(const char *arr, char *output, int output_size);
void unpadding_128bit(const char *arr, int arr_len, char output[16]);
char *concat(char *s1, int s1_len, char *s2, int s2_len);

void rsa_encrypt(char *text, int len, RSA *key, bool is_public_key, char *output);
void rsa_decrypt(char *text, int len, RSA *key, bool is_public_key, char *output);
void get_aes_key(char output[AES_KEY_SIZE]);
void aes_encrypt(char *text, int len, const uint8_t key[AES_KEY_SIZE], const uint8_t iv[AES_KEY_SIZE]);
void aes_decrypt(char *text, int len, const uint8_t key[AES_KEY_SIZE], const uint8_t iv[AES_KEY_SIZE]);

void print_hex(const char *s, int length) {
    for(int i = 0; i < length; i++) {
        printf("%02x", (unsigned char)s[i]);
    }
}

void _print(const char *pre, const char *s, int len) {
    printf("%s", pre);
    print_hex(s, len);
    printf("\n");
}

int hybrid_encrypt(keys_t *keys, char *message, int len, char **output) {
    if (*output) {
        free(*output);
        *output = NULL;
    }

    char aes_key[AES_KEY_SIZE];
    char aes_iv[AES_KEY_SIZE];
    char aes_key_padded[PADDING_SIZE];
    char md5[MD5_DIGEST_LENGTH];
    char md5_padded[PADDING_SIZE];
    char rsa_md5[PADDING_SIZE];
    char rsa_aes_key[PADDING_SIZE];

    fill_random(aes_key, AES_KEY_SIZE);
    fill_random(aes_iv, AES_KEY_SIZE);
    _print("AES_key=", aes_key, AES_KEY_SIZE);
    _print("AES_IV=", aes_iv, AES_KEY_SIZE);

    padding_128bit(aes_key, aes_key_padded, PADDING_SIZE);
    memcpy(aes_key_padded + PADDING_SIZE - AES_KEY_SIZE - AES_KEY_SIZE, aes_iv, 16);
    _print("AES_key_padding=", aes_key_padded, PADDING_SIZE);

    hash_md5(message, len, (uint8_t *)md5);
    _print("MD5=", md5, MD5_DIGEST_LENGTH);

    padding_128bit(md5, md5_padded, PADDING_SIZE);
    _print("MD5_padding=", md5_padded, PADDING_SIZE);

    rsa_encrypt(md5_padded, PADDING_SIZE, keys->pri, false, rsa_md5);
    _print("RSA_MD5_hash=", rsa_md5, PADDING_SIZE);

    int sign_len = len + PADDING_SIZE;
    int sign_padded_len = sign_len / 16;
    if (sign_len % 16) sign_padded_len += 1;
    sign_padded_len *= 16;

    char *sign = calloc(sign_padded_len, sizeof(char));

    if (!sign) {
        set_error(OutOfMemory);
        return 0;
    }

    memcpy(sign, rsa_md5, PADDING_SIZE);
    memcpy(sign + PADDING_SIZE, message, len);

    aes_encrypt(sign, sign_padded_len, (uint8_t *)aes_key, (uint8_t *)aes_iv);
    _print("AES_cipher=", sign, sign_padded_len);

    rsa_encrypt(aes_key_padded, PADDING_SIZE, keys->other, true, rsa_aes_key);
    _print("RSA_AES_key=", rsa_aes_key, PADDING_SIZE);

    int cipher_len = PADDING_SIZE + sign_padded_len;
    char *tmp = malloc(cipher_len);

    if (!tmp) {
        return 0;
    }

    memcpy(tmp, rsa_aes_key, PADDING_SIZE);
    memcpy(tmp + PADDING_SIZE, sign, sign_padded_len);

    free(sign);
    *output = tmp;

    return cipher_len;
}

int hybrid_decrypt(keys_t *keys, char *message, int len, char **output, bool *integrity_check) {
    if (*output) {
        free(*output);
        *output = NULL;
    }

    if (len < (PADDING_SIZE * 2)) {
        set_error(MessageTooShort);
        return 0;
    }

    if ((len - PADDING_SIZE) % 16 != 0) {
        set_error(InvalidEncryptedMessage);
        return 0;
    }

    int aes_msg_len = len - PADDING_SIZE;
    _print("RSA_AES_key=", message, PADDING_SIZE);
    _print("AES_cipher=", message + PADDING_SIZE, aes_msg_len);

    char aes_key_padded[PADDING_SIZE];
    uint8_t aes_key[AES_KEY_SIZE];
    uint8_t aes_iv[AES_KEY_SIZE];
    char md5_padded[PADDING_SIZE];
    char md5_sign[MD5_DIGEST_LENGTH];
    uint8_t md5[MD5_DIGEST_LENGTH];

    rsa_decrypt(message, PADDING_SIZE, keys->pri, false, aes_key_padded);
    unpadding_128bit(aes_key_padded, PADDING_SIZE, (char *)aes_key);
    _print("AES_key=", (char *)aes_key, AES_KEY_SIZE);

    memcpy(aes_iv, aes_key_padded + PADDING_SIZE - AES_KEY_SIZE * 2, AES_KEY_SIZE);
    _print("AES_IV=", (char *)aes_iv, AES_KEY_SIZE);

    char aes_msg[aes_msg_len];
    memcpy(aes_msg, message + PADDING_SIZE, aes_msg_len);
    aes_decrypt(aes_msg, aes_msg_len, aes_key, aes_iv);

    rsa_decrypt(aes_msg, PADDING_SIZE, keys->other, true, md5_padded);
    unpadding_128bit(md5_padded, PADDING_SIZE, md5_sign);
    _print("MD5_sign=", md5_sign, MD5_DIGEST_LENGTH);
    int msg_len = 0;
    char *tmp = malloc(aes_msg_len - PADDING_SIZE);

    if (!tmp) {
        set_error(OutOfMemory);
        return 0;
    }

    for (int i = PADDING_SIZE; i < aes_msg_len && aes_msg[i]; i++) {
        tmp[msg_len++] = aes_msg[i];
    }

    *output = tmp;
    hash_md5(tmp, msg_len, md5);
    *integrity_check = memcmp(md5, md5_sign, MD5_DIGEST_LENGTH) == 0;

    return msg_len;
}

void generate_rsa_keys(const char *public_path, const char *private_path) {
    mkdir("./cert", 0700);

    if (access(public_path, F_OK) == 0 && access(private_path, F_OK) == 0) {
        return;
    }

    // generate new key
    int keylen = 2048;

    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    if (BN_set_word(e, RSA_F4) != 1) {
        set_error(KeygenError);
        RSA_free(rsa);
        BN_free(e);
        return;
    }

    if (RSA_generate_key_ex(rsa, keylen, e, NULL) != 1) {
        set_error(KeygenError);
        RSA_free(rsa);
        BN_free(e);
        return;
    }

    FILE *file = fopen(public_path, "w");
    if (PEM_write_RSAPublicKey(file, rsa) != 1) {
        set_error(KeygenError);
        fclose(file);
        RSA_free(rsa);
        BN_free(e);
        return;
    }

    fclose(file);

    file = fopen(private_path, "w");
    if (PEM_write_RSAPrivateKey(file, rsa, NULL, NULL, 0, NULL, NULL) != 1) {
        set_error(KeygenError);
    }

    fclose(file);

    RSA_free(rsa);
    BN_free(e);
}

RSA *rsa_read_key(const char *filename, bool is_public) {
    FILE *file = fopen(filename, "r");

    if (!file) {
        set_error(FileNotFound);
        return NULL;
    }

    RSA *key = is_public
        ? PEM_read_RSAPublicKey(file, NULL, NULL, NULL)
        : PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);

    fclose(file);
    return key;
}

keys_t read_keys(const char *pub, const char *pri, const char *other) {
    keys_t keys;
    keys.pub = rsa_read_key(pub, true);
    keys.pri = rsa_read_key(pri, false);
    keys.other = rsa_read_key(other, true);

    if (!keys.pub || !keys.pri || !keys.other) {
        free_keys(keys);
        set_error(CannotReadKey);
    }

    return keys;

}
void free_keys(keys_t keys) {
    RSA_free(keys.pub);
    RSA_free(keys.pri);
    RSA_free(keys.other);
}

void rsa_encrypt(char *text, int len, RSA *key, bool is_public_key, char *output) {
    if (is_public_key) {
        RSA_public_encrypt(
            len,
            (unsigned char *)text, 
            (unsigned char *)output, 
            key, 
            RSA_NO_PADDING
        );
    } else {
        RSA_private_encrypt(
            len,
            (unsigned char *)text, 
            (unsigned char *)output, 
            key, 
            RSA_NO_PADDING
        );
    }
}

void rsa_decrypt(char *text, int len, RSA *key, bool is_public_key, char *output) {
    if (is_public_key) {
        RSA_public_decrypt(
            len,
            (const unsigned char *)text, 
            (unsigned char *)output, 
            key, 
            RSA_NO_PADDING
        );
    } else {
        RSA_private_decrypt(
            len,
            (const unsigned char *)text, 
            (unsigned char *)output, 
            key, 
            RSA_NO_PADDING
        );
    }
}

void aes_encrypt(char *text, int len, const uint8_t key[AES_KEY_SIZE], const uint8_t iv[AES_KEY_SIZE]) {
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, (uint8_t *)text, len);
}

void aes_decrypt(char *text, int len, const uint8_t key[AES_KEY_SIZE], const uint8_t iv[AES_KEY_SIZE]) {
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, (uint8_t *)text, len);
}

void hash_md5(const char *text, int len, uint8_t output[MD5_DIGEST_LENGTH]) {
    MD5((const char unsigned *)text, len, output);
}

void padding_128bit(const char *arr, char *output, int output_size) {
    int urandom = open("/dev/urandom", O_RDONLY);
    output[0] = 0;
    read(urandom, output + 1, output_size - 17);
    close(urandom);

    for (int i = 0; i < 16; i++) {
        output[output_size - 16 + i] = arr[i];
    }
}

void unpadding_128bit(const char *arr, int arr_len, char output[16]) {
    memcpy(output, arr + arr_len - 16, 16);
}

void fill_random(char *output, int length) {
    int urandom = open("/dev/urandom", O_RDONLY);
    read(urandom, output, length);
    close(urandom);
}
