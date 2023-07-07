#include <openssl/x509.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdint.h>

#include "client.h"
#include "server.h"
#include "crypto.h"
#include "error.h"

typedef enum {
    Client,
    Server,
} Mode;

typedef struct {
    uint16_t port;
    Mode mode;
} Arguments;

Arguments arguments_parse(int argc, char **argv) {
    Arguments args;

    if (argc != 3) {
        set_error(InvalidArguments);
        return args;
    }

    switch (*argv[1]) {
        case 'c': args.mode = Client; break;
        case 's': args.mode = Server; break;
        default: 
            set_error(InvalidArguments);
            return args;
    }
    
    args.port = atoi(argv[2]);

    return args;
}

#define CHUNK_SIZE 64

/// Read line from stdin
/// @return number of byte have read
int read_line(char **output) {
    if (*output) {
        free(*output);
        *output = NULL;
    }

    int total_length = 0;
    int ch;

    while ((ch = getchar()) != EOF && ch != '\n') {
        if ((total_length % CHUNK_SIZE) == 0) {
            char *tmp = realloc(*output, (total_length + CHUNK_SIZE) * sizeof(char));

            if (!tmp) {
                set_error(OutOfMemory);
                free(*output);
                return -1;
            }

            *output = tmp;
        }

        (*output)[total_length++] = ch;
    }

    return total_length;
}

void run_client(short port) {
    generate_rsa_keys("./cert/client_public.pem", "./cert/client_private.pem");

    connect_to(port);
    if (got_error()) return;

    printf("Successfully connected server\n");

    if (got_error()) return;

    keys_t keys = read_keys(
        "./cert/client_public.pem",
        "./cert/client_private.pem",
        "./cert/server_public.pem"
    );

    if (got_error()) return;

    printf("RSA_public_key_sender\n");
    PEM_write_RSAPublicKey(stdout, keys.pub);
    printf("\n");
    printf("RSA_private_key_sender=\n");
    PEM_write_RSAPrivateKey(stdout, keys.pri, NULL, NULL, 0, NULL, NULL);
    printf("\n");
    printf("RSA_public_key_receiver=\n");
    PEM_write_RSAPublicKey(stdout, keys.other);
    printf("\n");

    char *msg = NULL;
    char *encrypt_msg = NULL;
    char nonce[16];
    char server_resp[16];
    char nonce_hash[MD5_DIGEST_LENGTH];

    for(;;) {
        printf("Enter input: ");
        int length = read_line(&msg);
        if (got_error()) break;

        int encrypted_len = hybrid_encrypt(&keys, msg, length, &encrypt_msg);
        printf("ciphertext=");
        print_hex(encrypt_msg, encrypted_len);
        printf("\n");

        bool success = false;

        while (!success) {
            fill_random(nonce, 16);

            printf("nonce=");
            print_hex(nonce, 16);
            printf("\n");

            int msg_len = encrypted_len + 16;
            char *to_send = malloc(msg_len);

            if (!to_send) {
                set_error(OutOfMemory);
                return;
            }

            memcpy(to_send, nonce, 16);
            memcpy(to_send + 16, encrypt_msg, encrypted_len);

            send_msg(to_send, msg_len);

            free(to_send);
            if (got_error()) break;

            /// check response nonce hash with msg
            recv_msg(server_resp, 16);
            if (got_error()) break;

            char nonce_msg[16 + length];

            memcpy(nonce_msg, nonce, 16);
            memcpy(nonce_msg + 16, msg, length);

            hash_md5(nonce_msg, 16 + length, (uint8_t *)nonce_hash);

            success = memcmp(nonce_hash, server_resp, 16) == 0;

            if (success) {
                printf("The message was successfully delivered\n");
            } else {
                printf("Failed to send the message securely, trying again\n");
            }
        }

    }

    if (msg) free(msg);
    if (encrypt_msg) free(encrypt_msg);
    free_keys(keys);
    disconnect();
}

void run_server(short port) {
    listen_on(port);

    if (got_error()) return;

    generate_rsa_keys("./cert/server_public.pem", "./cert/server_private.pem");

    if (got_error()) return;

    int client = accept_connection();

    if (got_error()) {
        return;
    }

    keys_t keys = read_keys(
        "./cert/server_public.pem",
        "./cert/server_private.pem",
        "./cert/client_public.pem"
    );

    if (got_error()) return;

    printf("RSA_public_key_receiver\n");
    PEM_write_RSAPublicKey(stdout, keys.pub);
    printf("\n");
    printf("RSA_private_key_receiver=\n");
    PEM_write_RSAPrivateKey(stdout, keys.pri, NULL, NULL, 0, NULL, NULL);
    printf("\n");
    printf("RSA_public_key_sender\n");
    PEM_write_RSAPublicKey(stdout, keys.other);
    printf("\n");

    char *incoming = NULL;
    char *msg = NULL;
    char nonce_hash_resp[16] = {0};
    bool integrity_check;

    while (!got_error()) {
        int len = receive_message(client, &incoming);

        if (got_error()) break;
        printf("nonce=");
        print_hex(incoming, 16);
        printf("\n");

        printf("ciphertext=");
        print_hex(incoming + 16, len - 16);
        printf("\n");

        int msg_len = hybrid_decrypt(&keys, incoming + 16, len - 16, &msg, &integrity_check);
        
        if (got_error()) break;

        printf("plaintext=%.*s\n", msg_len, msg);

        if (integrity_check) {
            printf("The integrity of the message has been compromised\n");
            int nonce_msg_len = 16 + msg_len;
            char nonce_msg[nonce_msg_len];
            memcpy(nonce_msg, incoming, 16);
            memcpy(nonce_msg + 16, msg, msg_len);

            hash_md5(nonce_msg, nonce_msg_len, (uint8_t *)nonce_hash_resp);
        } else {
            printf("The integrity of the message has not been compromised\n");
            fill_random(nonce_hash_resp, 16);
        }

        send_message(client, nonce_hash_resp, 16);
    }

    if (incoming) free(incoming);
    if (msg) free(msg);
    free_keys(keys);
    server_close();
}

int main(int argc, char **argv) {
    Arguments args = arguments_parse(argc, argv);

    if (!got_error()) {
        switch (args.mode) {
            case Client:
                run_client(args.port);
                break;
            case Server:
                run_server(args.port);
                break;
        }
    }

    print_error_msg();
    return got_error();
}
