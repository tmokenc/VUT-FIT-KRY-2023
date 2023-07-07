#ifndef CRYPTO_H__
#define CRYPTO_H__

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <stdbool.h>

typedef struct {
    RSA *pub;
    RSA *pri;
    RSA *other;
} keys_t;

void generate_rsa_keys(const char *public_path, const char *private_path);

keys_t read_keys(const char *pub, const char *pri, const char *other);
void free_keys(keys_t key);

/// fill the output will random data
void fill_random(char *output, int length);

/// Hash the text
void hash_md5(const char *text, int len, uint8_t output[MD5_DIGEST_LENGTH]);

/// @params key Keys to use for encryption
/// @params message Message to be encrypted
/// @params len Length of the message
/// @params[out] output Encrypted message will be written here
/// @return encrypted message size
int hybrid_encrypt(keys_t *key, char *message, int len, char **output);

/// @params key Keys to use for decryption
/// @params message Encrypted message
/// @params len Length of the encrypted message
/// @params[out] output Decrypted message will be written here
/// @params[out] integrity_check Wherther the integrity of the message has been compromised or not
/// @return decrypted message size
int hybrid_decrypt(keys_t *key, char *message, int len, char **output, bool *integrity_check);

/// Print the string as hex
void print_hex(const char *s, int length);

void generate_rsa_keys(const char *public_path, const char *private_path);




#endif
