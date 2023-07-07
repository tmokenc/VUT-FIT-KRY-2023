#ifndef SERVER_H__
#define SERVER_H__

/// Start a localhost server on specific port
void listen_on(short port);

// @return file descriptor for the connected client
int accept_connection();

/// @params client the client file descriptor
/// @params[out] output pointer to the output string, this will be dynamically allocated
/// @return how many byte was read
int receive_message(int client, char **output);

/// @params client Client FD
/// @params msg the message to be sent
/// @params size the size of the message
void send_message(int client, const char *msg, int size);

void server_close();

#endif
