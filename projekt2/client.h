#ifndef CLIENT_H__
#define CLIENT_H__

/// Connect to a server running on localhost
void connect_to(short port);

/// Send message to the server, this will send 4 bytes about data length first (MSB)
void send_msg(const char *msg, int size);

/// Receive a message from server
void recv_msg(char *output, int size);

void disconnect();


#endif
