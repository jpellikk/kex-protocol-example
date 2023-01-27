#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>

#define MAX_ECDH_SHARED_SECET_SIZE 64
#define AES_CMAC_BLOCK_SIZE 16

#pragma pack(push,1)

struct keymat
{
  unsigned char initiator_ik[AES_CMAC_BLOCK_SIZE];
  unsigned char initiator_ek[AES_CMAC_BLOCK_SIZE];
  unsigned char responder_ik[AES_CMAC_BLOCK_SIZE];
  unsigned char responder_ek[AES_CMAC_BLOCK_SIZE];
};

#pragma pack(pop)

int generate_random_bytes(unsigned char *buffer, int num_bytes);
int ec_public_key_to_bytes(EVP_PKEY *key, unsigned char *buffer);
int ec_key_short_name_to_nid(const char *name);
int ec_key_to_nid(EVP_PKEY *key);
EVP_PKEY *create_ec_key_from_pem_file(const char *filename);
EVP_PKEY *create_ec_key_from_bytes(int curve_nid, const unsigned char *bytes, int bytes_len);
EVP_PKEY *generate_ec_keypair(int curve_nid);
int ecdh(EVP_PKEY *private_key, EVP_PKEY *public_key, unsigned char *out, size_t out_len, size_t *secret_len);
int generate_keymat(struct keymat *keymat, const unsigned char *shared_secret, size_t shared_secret_len, const unsigned char *nonce_a, size_t nonce_a_len, const unsigned char *nonce_b, size_t nonce_b_len);
int calculate_mac(const unsigned char *in, size_t in_len, const unsigned char *key, size_t key_len, unsigned char *out, size_t out_len);

#endif
