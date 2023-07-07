/// @file error.c
/// @author Le Duy Nguyen, xnguye27, VUT FIT
/// @date 01/03/2023
/// @brief Implementation of functions defined in `error.h` file

#include <stdio.h>
#include "error.h"

const char *MSG[] = {
    [1] = "Invalid Arguments",
    "File Not Found",
    "Out Of Memory",
    "Got error while generating RSA2048 public/private keys",
    "Cannot read RSA key",
    "The message is too short",
    "The encrypted message is invalid",
    // Client
    "Cannot connect",
    "Cannot send message",
    // Server
    "Socket Error",
    "Cannot bind IP address",
    "CannotListenOnSocket",
    "Error accept connection",
    "Cannot receive message from the client",
};

enum error ERROR = Ok;

void set_error(enum error err) {
    ERROR = err;
}

enum error got_error() {
    return ERROR;
}

void print_error_msg() {
    if (ERROR) {
        fprintf(stderr, "ERROR: %s\n", MSG[ERROR]);
    }
}
