#include "message.h"
#include "socket.h"
#include "crypto.h"
#include "helper.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_LENGTH 1500

struct responder_context
{
  EVP_PKEY* host_ec_key;
  EVP_PKEY* peer_ec_key;
  int curve_nid;
  unsigned char nonce_a[SIZE_NONCE];
  unsigned char nonce_b[SIZE_NONCE];
  struct keymat keymat;
};

static struct responder_context context = {0};

static void cleanup()
{
  socket_close();
  EVP_PKEY_free(context.host_ec_key);
  EVP_PKEY_free(context.peer_ec_key);
}

static int handle_first_message()
{
  int nbytes;
  unsigned char buffer[BUFFER_LENGTH];
  struct MSG_FIRST *msg = (struct MSG_FIRST*)buffer;

  if ((nbytes = socket_receive(buffer, sizeof(buffer))) < 0) {
    return -1;
  }

  if (nbytes != sizeof(*msg) || msg->type != MSG_TYPE_FIRST) {
    return -1;
  }

  if (msg->curve != ec_key_to_nid(context.host_ec_key)) {
    fprintf(stderr, "Initiator's curve not supported.\n");
    return -1;
  }

  context.curve_nid = msg->curve;

  if (generate_random_bytes(context.nonce_a, sizeof(context.nonce_a)) != 1) {
    fprintf(stderr, "Generating nonce A failed.\n");
    return -1;
  }

  return 0;
}

static int send_second_message()
{
  struct MSG_SECOND msg = {0};

  msg.type = MSG_TYPE_SECOND;
  msg.curve = context.curve_nid;
  msg.pubkey_len = ec_public_key_to_bytes(context.host_ec_key, NULL);

  if (msg.pubkey_len > sizeof(msg.pubkey)) {
    fprintf(stderr, "Our public key is too long to fit in pubkey field.\n");
    return -1;
  }

  ec_public_key_to_bytes(context.host_ec_key, msg.pubkey);
  memcpy(msg.nonce_a, context.nonce_a, sizeof(msg.nonce_a));

  if (socket_send((unsigned char*)&msg, sizeof(msg)) < 1) {
    return -1;
  }

  return 0;
}

static int handle_third_message()
{
  int nbytes;
  size_t shared_secret_len;
  unsigned char buffer[BUFFER_LENGTH];
  struct MSG_THIRD *msg = (struct MSG_THIRD*)buffer;
  unsigned char shared_secret[MAX_ECDH_SHARED_SECET_SIZE];
  unsigned char mac_value[SIZE_MAC];

  if ((nbytes = socket_receive(buffer, sizeof(buffer))) < 0) {
    return -1;
  }

  if (nbytes != sizeof(*msg) || msg->type != MSG_TYPE_THIRD) {
    return -1;
  }

  if (msg->pubkey_len > sizeof(msg->pubkey)) {
    return -1;
  }

  if (memcmp(context.nonce_a, msg->nonce_a, sizeof(context.nonce_a)) != 0) {
    fprintf(stderr, "Nonce A value verification failed.\n");
    return -1;
  }

  if (!(context.peer_ec_key = create_ec_key_from_bytes(
    context.curve_nid, msg->pubkey, msg->pubkey_len))) {
    fprintf(stderr, "Creating peer EC public key failed.\n");
    return -1;
  }

  if (ecdh(context.host_ec_key, context.peer_ec_key,
    shared_secret, sizeof(shared_secret), &shared_secret_len) < 0) {
    fprintf(stderr, "Calculating ECDH shared key failed.\n");
    return -1;
  }

  print_ecdh_key(stdout, shared_secret, shared_secret_len);

  if (generate_keymat(&context.keymat, shared_secret, shared_secret_len,
    context.nonce_a, sizeof(context.nonce_a), msg->nonce_b, sizeof(msg->nonce_b)) < 0) {
    fprintf(stderr, "Generating integrity and encryption keys failed.\n");
    return -1;
  }

  print_keymat(stdout, &context.keymat);

  if (calculate_mac((const unsigned char*)msg, sizeof(*msg) - sizeof(msg->mac),
    context.keymat.initiator_ik, sizeof(context.keymat.initiator_ik),
    mac_value, sizeof(mac_value)) < 0) {
    fprintf(stderr, "Calculating MAC failed.\n");
    return -1;
  }

  if (memcmp(mac_value, msg->mac, sizeof(mac_value)) != 0) {
    fprintf(stderr, "MAC value verification failed.\n");
    return -1;
  }

  memcpy(context.nonce_b, msg->nonce_b, sizeof(msg->nonce_b));

  return 0;
}

static int send_fourth_message()
{
  struct MSG_FOURTH msg = {0};

  msg.type = MSG_TYPE_FOURTH;
  memcpy(msg.nonce_b, context.nonce_b, sizeof(msg.nonce_b));

  if (calculate_mac((const unsigned char*)&msg, sizeof(msg) - sizeof(msg.mac),
    context.keymat.responder_ik, sizeof(context.keymat.responder_ik),
    msg.mac, sizeof(msg.mac)) < 0) {
    fprintf(stderr, "Calculating MAC failed.\n");
    return -1;
  }

  if (socket_send((unsigned char*)&msg, sizeof(msg)) < 1) {
    return -1;
  }

  return 0;
}

int main(int argc, char **argv)
{
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <port> <pemfile>\n", argv[0]);
    goto error;
  }

  if (socket_server(atoi(argv[1])) < 0) {
    fprintf(stderr, "Creating socket failed.\n");
    goto error;
  }

  if (!(context.host_ec_key = create_ec_key_from_pem_file(argv[2]))) {
    fprintf(stderr, "Creating EC key from file failed.\n");
    goto error;
  }

  if (handle_first_message() < 0) {
    fprintf(stderr, "Handling message FIRST failed.\n");
    goto error;
  }

  if (send_second_message() < 0) {
    fprintf(stderr, "Sending message SECOND failed.\n");
    goto error;
  }

  if (handle_third_message() < 0) {
    fprintf(stderr, "Handling message THIRD failed.\n");
    goto error;
  }

  if (send_fourth_message() < 0) {
    fprintf(stderr, "Sending message FOURTH failed.\n");
    goto error;
  }

  cleanup();
  fprintf(stdout, "Key exchange completed successfully.\n");
  return EXIT_SUCCESS;

error:
  cleanup();
  return EXIT_FAILURE;
}
