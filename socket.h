#ifndef SOCKET_H
#define SOCKET_H

int socket_server(const int port);
int socket_client(const char *hostname, int port);
int socket_send(unsigned char *buffer, int length);
int socket_receive(unsigned char *buffer, int length);
int socket_close();

#endif
