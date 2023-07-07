/// @file error.h
/// @author Le Duy Nguyen, xnguye27, VUT FIT
/// @date 01/03/2023
/// @brief Define the `Error` enum type and its related function to be used for error handling in the project 

#ifndef ERROR_H
#define ERROR_H

#ifdef NDEBUG
#define debug(s)
#define dfmt(s, ...)
#else

// Print the debug string into `stderr`
#define debug(s) fprintf(stderr, __FILE__":%u: %s\n",__LINE__, s)

// Print the debug string with format like printf
#define dfmt(s, ...) fprintf(stderr, __FILE__":%u: "s"\n",__LINE__,__VA_ARGS__)

#endif

enum error {
    Ok,

    InvalidArguments,
    FileNotFound,
    OutOfMemory,

    // Crypto
    KeygenError,
    CannotReadKey,
    MessageTooShort,
    InvalidEncryptedMessage,

    // Client
    CannotConnect,
    CannotSendMessage,
    // Server
    SocketError,
    CannotBind,
    CannotListenOnSocket,
    CannotAccept,
    CannotReceiveMessage,
};

void set_error(enum error);

enum error got_error();

/// @brief Print the `error` message to `stderr`
void print_error_msg();

#endif
