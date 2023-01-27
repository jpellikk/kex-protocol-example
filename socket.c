#include "socket.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

static int sock = -1;
static struct sockaddr_in si_peer;

int socket_server(int port)
{
  struct sockaddr_in si_local;

  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    return -1;
  }

  memset((char*)&si_local, 0, sizeof(si_local));
  si_local.sin_family = AF_INET;
  si_local.sin_port = htons(port);
  si_local.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(sock, (struct sockaddr*)&si_local, sizeof(si_local)) == -1) {
    close(sock);
    return -1;
  }

  return sock;
}

int socket_client(const char *hostname, int port)
{
  struct hostent *host;

  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    return -1;
  }

  if (!(host = gethostbyname(hostname))) {
    close(sock);
    return -1;
  }

  memset((char*)&si_peer, 0, sizeof(si_peer));
  si_peer.sin_family = AF_INET;
  si_peer.sin_port = htons(port);
  si_peer.sin_addr = *((struct in_addr *)host->h_addr);

  return sock;
}

int socket_close()
{
  int result = 0;

  if (sock > 0) {
    result = close(sock);
    sock = -1;
  }

  return result;
}

int socket_send(unsigned char *buffer, int length)
{
  return sendto(sock, buffer, length, 0x00, (struct sockaddr*)&si_peer, sizeof(si_peer));
}

int socket_receive(unsigned char *buffer, int length)
{
  socklen_t si_peer_len = sizeof(si_peer);
  return recvfrom(sock, buffer, length, 0x00, (struct sockaddr*)&si_peer, &si_peer_len);
}
