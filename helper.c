#include "helper.h"

static void print_byte_array(FILE *fp, const unsigned char *bytes, size_t bytes_len)
{
  size_t i;
  for (i = 0; i < bytes_len; ++i) {
    fprintf(fp, "%02X", bytes[i]);
  }
}

void print_ecdh_key(FILE *fp, const unsigned char *key, size_t key_len)
{
  fprintf(fp, "ECDH shared secret length: %lu\n", key_len);
  fprintf(fp, "ECDH shared secret bytes: ");
  print_byte_array(fp, key, key_len);
  fprintf(fp, "\n");
}

void print_keymat(FILE *fp, const struct keymat *keymat)
{
  fprintf(fp, "Initiator IK: ");
  print_byte_array(fp, keymat->initiator_ik,
    sizeof(keymat->initiator_ik));
  fprintf(fp, "\n");

  fprintf(fp, "Initiator EK: ");
  print_byte_array(fp, keymat->initiator_ek,
    sizeof(keymat->initiator_ek));
  fprintf(fp, "\n");

  fprintf(fp, "Responder IK: ");
  print_byte_array(fp, keymat->responder_ik,
    sizeof(keymat->responder_ik));
  fprintf(fp, "\n");

  fprintf(fp, "Responder EK: ");
  print_byte_array(fp, keymat->responder_ek,
    sizeof(keymat->responder_ek));
  fprintf(fp, "\n");
}
