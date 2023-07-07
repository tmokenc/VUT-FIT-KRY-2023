#include "server.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "error.h"
#include <stdlib.h>

int sockfd;

/// Start a localhost server on specific port
void listen_on(short port) {
    struct sockaddr_in server_addr;

    // create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        set_error(SocketError);
        return;
    }

    // set server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

    // bind socket to address
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        set_error(CannotBind);
        return;
    }

    // listen for connections
    if (listen(sockfd, 5) != 0) {
        set_error(CannotListenOnSocket);
        return;
    }
}

int accept_connection() {
    int clientfd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    // accept connection from client
    clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (clientfd < 0) {
        set_error(CannotAccept);
    }

    return clientfd;
}

int msb_to_num(char byte[4]) {
    int num = 0;

    for (int i = 3; i >= 0; i--) {
        num <<= 8;
        num |= (unsigned char)byte[i];
    }

    return num;
}

void send_message(int client, const char *msg, int size) {
    int byte_send = send(client, msg, size, 0);
    set_error(byte_send == -1 ? CannotSendMessage : Ok);
}

int receive_message(int client, char **output) {
    if (*output) {
        free(*output);
        *output = NULL;
    }

    char msb[4];

    if (read(client, msb, 4) != 4) {
        set_error(CannotReceiveMessage);
        return -1;
    }

    int size = msb_to_num(msb);
    char *tmp = malloc(sizeof(char) * size);

    if (!tmp) {
        set_error(OutOfMemory);
        return -1;
    }

    if (read(client, tmp, size) != size) {
        set_error(CannotReceiveMessage);
        free(tmp);
        return -1;
    }

    *output = tmp;

    return size;
}
 

void server_close() {
    close(sockfd);
}
