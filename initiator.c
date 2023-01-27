#include "message.h"
#include "socket.h"
#include "crypto.h"
#include "helper.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_LENGTH 1500

struct initiator_context
{
  EVP_PKEY* host_ec_key;
  EVP_PKEY* peer_ec_key;
  int curve_nid;
  unsigned char nonce_a[SIZE_NONCE];
  unsigned char nonce_b[SIZE_NONCE];
  struct keymat keymat;
};

static struct initiator_context context = {0};

static void cleanup()
{
  socket_close();
  EVP_PKEY_free(context.host_ec_key);
  EVP_PKEY_free(context.peer_ec_key);
}

static int send_first_message()
{
  struct MSG_FIRST msg = {0};

  msg.type = MSG_TYPE_FIRST;
  msg.curve = context.curve_nid;

  if (socket_send((unsigned char*)&msg, sizeof(msg)) < 0) {
     return -1;
  }

  return 0;
}

static int handle_second_message()
{
  int nbytes;
  size_t shared_secret_len;
  unsigned char buffer[BUFFER_LENGTH];
  struct MSG_SECOND *msg = (struct MSG_SECOND*)buffer;
  unsigned char shared_secret[MAX_ECDH_SHARED_SECET_SIZE];

  if ((nbytes = socket_receive(buffer, sizeof(buffer))) < 0) {
    return -1;
  }

  if (nbytes != sizeof(*msg) || msg->type != MSG_TYPE_SECOND) {
    return -1;
  }

  if (context.curve_nid != msg->curve) {
    fprintf(stderr, "Peer sent wrong curve nid value.\n");
    return -1;
  }

  if (msg->pubkey_len > sizeof(msg->pubkey)) {
    return -1;
  }

  if (!(context.peer_ec_key = create_ec_key_from_bytes(
    msg->curve, msg->pubkey, msg->pubkey_len))) {
    fprintf(stderr, "Creating peer EC public key failed.\n");
    return -1;
  }

  /* Generate an epheremal EC keypair for the ECDH key exchange */
  if (!(context.host_ec_key = generate_ec_keypair(context.curve_nid))) {
    fprintf(stderr, "Creating host EC public/private keypair failed.\n");
    return -1;
  }

  if (ecdh(context.host_ec_key, context.peer_ec_key,
    shared_secret, sizeof(shared_secret), &shared_secret_len) < 0) {
    fprintf(stderr, "Calculating ECDH shared key failed.\n");
    return -1;
  }

  print_ecdh_key(stdout, shared_secret, shared_secret_len);

  if (generate_random_bytes(context.nonce_b, sizeof(context.nonce_b)) != 1) {
    fprintf(stderr, "Generating nonce B failed.\n");
    return -1;
  }

  if (generate_keymat(&context.keymat, shared_secret, shared_secret_len,
    msg->nonce_a, sizeof(msg->nonce_a), context.nonce_b, sizeof(context.nonce_b)) < 0) {
    fprintf(stderr, "Generating integrity and encryption keys failed.\n");
    return -1;
  }

  print_keymat(stdout, &context.keymat);

  memcpy(context.nonce_a, msg->nonce_a, sizeof(msg->nonce_a));

  return 0;
}

static int send_third_message()
{
  struct MSG_THIRD msg = {0};

  msg.type = MSG_TYPE_THIRD;
  msg.pubkey_len = ec_public_key_to_bytes(context.host_ec_key, NULL);

  if (msg.pubkey_len > sizeof(msg.pubkey)) {
    fprintf(stderr, "Our public key is too long to fit in pubkey field.\n");
    return -1;
  }

  ec_public_key_to_bytes(context.host_ec_key, msg.pubkey);

  memcpy(msg.nonce_a, context.nonce_a, sizeof(msg.nonce_a));
  memcpy(msg.nonce_b, context.nonce_b, sizeof(msg.nonce_b));

  if (calculate_mac((const unsigned char*)&msg, sizeof(msg) - sizeof(msg.mac),
    context.keymat.initiator_ik, sizeof(context.keymat.initiator_ik),
    msg.mac, sizeof(msg.mac)) < 0) {
    fprintf(stderr, "Calculating MAC failed.\n");
    return -1;
  }

  if (socket_send((unsigned char*)&msg, sizeof(msg)) < 0) {
     return -1;
  }

  return 0;
}

static int handle_fourth_message()
{
  int nbytes;
  unsigned char buffer[BUFFER_LENGTH];
  struct MSG_FOURTH *msg = (struct MSG_FOURTH*)buffer;
  unsigned char mac_value[SIZE_MAC];

  if ((nbytes = socket_receive(buffer, sizeof(buffer))) < 0) {
    return -1;
  }

  if (nbytes != sizeof(*msg) || msg->type != MSG_TYPE_FOURTH) {
    return -1;
  }

  if (memcmp(context.nonce_b, msg->nonce_b, sizeof(context.nonce_b)) != 0) {
    fprintf(stderr, "Nonce B value verification failed.\n");
    return -1;
  }

  if (calculate_mac((const unsigned char*)msg, sizeof(*msg) - sizeof(msg->mac),
    context.keymat.responder_ik, sizeof(context.keymat.responder_ik),
    mac_value, sizeof(mac_value)) < 0) {
    fprintf(stderr, "Calculating MAC failed.\n");
    return -1;
  }

  if (memcmp(mac_value, msg->mac, sizeof(mac_value)) != 0) {
    fprintf(stderr, "MAC value verification failed.\n");
    return -1;
  }

  return 0;
}

int main(int argc, char **argv)
{
  if (argc < 4) {
    fprintf(stderr, "Usage: %s <hostname> <port> <curvename>\n", argv[0]);
    goto error;
  }

  if (socket_client(argv[1], atoi(argv[2])) < 0) {
    fprintf(stderr, "Creating socket failed.\n");
    goto error;
  }

  if ((context.curve_nid = ec_key_short_name_to_nid(argv[3])) == 0) {
    fprintf(stderr, "Unrecognized elliptic curve '%s'\n", argv[3]);
    goto error;
  }

  if (send_first_message() < 0) {
    fprintf(stderr, "Sending message FIRST failed.\n");
    goto error;
  }

  if (handle_second_message() < 0) {
    fprintf(stderr, "Handling message SECOND failed.\n");
    goto error;
  }

  if (send_third_message() < 0) {
    fprintf(stderr, "Sending message THIRD failed.\n");
    goto error;
  }

  if (handle_fourth_message() < 0) {
    fprintf(stderr, "Handling message FOURTH failed.\n");
    goto error;
  }

  cleanup();
  fprintf(stdout, "Key exchange completed successfully.\n");
  return EXIT_SUCCESS;

error:
  cleanup();
  return EXIT_FAILURE;
}
