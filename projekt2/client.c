#include "client.h"
#include "error.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int socketD = -1;

void connect_to(short port) {
    printf("CLIENT: Connecting to the port %u on localhost\n", port);
    printf("CLIENT: Connected\n");

    socketD = socket(AF_INET, SOCK_STREAM, 0);
  
    struct sockaddr_in servAddr;
  
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);
    servAddr.sin_addr.s_addr = INADDR_ANY;
  
    int connect_status = connect(socketD, (struct sockaddr*)&servAddr, sizeof(servAddr));
    set_error(connect_status == -1 ? CannotConnect : Ok);
}

void num_to_msb(int num, char byte[4]) {
   int idx = 0;

   while (num) {
       byte[idx++] = (unsigned char)(num & 0b11111111);
       num >>= 8;
   }
}

void recv_msg(char *output, int size) {
    if (read(socketD, output, size) != size) {
        set_error(CannotReceiveMessage);
    }
}

void send_msg(const char *msg, int size) {
    char msb[4];
    num_to_msb(size, msb);
    send(socketD, msb, 4, 0);
    int byte_send = send(socketD, msg, size, 0);
    set_error(byte_send == -1 ? CannotSendMessage : Ok);
}

void disconnect() {
    close(socketD);
    socketD = -1;
    printf("CLIENT: Disconnected\n");
    set_error(Ok);
}

