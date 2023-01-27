#include "crypto.h"

#include <openssl/decoder.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

int generate_random_bytes(unsigned char *buffer, int num_bytes)
{
  return RAND_bytes(buffer, num_bytes);
}

int ec_public_key_to_bytes(EVP_PKEY *key, unsigned char *buffer)
{
  return i2d_PublicKey(key, buffer == NULL ? NULL : &buffer);
}

int ec_key_short_name_to_nid(const char *name)
{
  int curve_nid = OBJ_sn2nid(name);
  return curve_nid == NID_undef ? 0 : curve_nid;
}

int ec_key_to_nid(EVP_PKEY *key)
{
  char group_name[16];
  size_t group_name_len;

  if (!EVP_PKEY_get_group_name(key, group_name, sizeof(group_name), &group_name_len)) {
    return NID_undef;
  }

  return OBJ_sn2nid(group_name);
}

EVP_PKEY *create_ec_key_from_pem_file(const char *filename)
{
  OSSL_DECODER_CTX *decoder_ctx = NULL;
  EVP_PKEY *ec_key = NULL;
  BIO *bio = NULL;

  bio = BIO_new_file(filename, "rb");

  if (!bio) {
    goto error;
  }

  decoder_ctx = OSSL_DECODER_CTX_new_for_pkey(
    &ec_key, "PEM", NULL, NULL, EVP_PKEY_KEYPAIR, NULL, NULL);

  if (!decoder_ctx) {
    goto error;
  }

  if (!OSSL_DECODER_from_bio(decoder_ctx, bio)) {
    goto error;
  }

  BIO_free(bio);
  OSSL_DECODER_CTX_free(decoder_ctx);
  return ec_key;

error:
  BIO_free(bio);
  OSSL_DECODER_CTX_free(decoder_ctx);
  return NULL;
}

EVP_PKEY *create_ec_key_from_bytes(int curve_nid, const unsigned char *bytes, int bytes_len)
{
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY *pkey = NULL, *params = NULL;

  if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
    goto error;
  }

  if (EVP_PKEY_paramgen_init(pctx) != 1) {
    goto error;
  }

  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid) != 1) {
    goto error;
  }

  if (!EVP_PKEY_paramgen(pctx, &params)) {
    goto error;
  }

  if ((pkey = d2i_PublicKey(EVP_PKEY_EC, &params, &bytes, bytes_len))) {
    EVP_PKEY_CTX_free(pctx);
    return pkey;
  }

error:
  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_free(params);
  return NULL;
}

EVP_PKEY *generate_ec_keypair(int curve_nid)
{
  EVP_PKEY_CTX *pctx = NULL, *kctx = NULL;
  EVP_PKEY *pkey = NULL, *params = NULL;

  if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
    goto error;
  }

  if (EVP_PKEY_paramgen_init(pctx) != 1) {
    goto error;
  }

  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid) != 1) {
    goto error;
  }

  if (!EVP_PKEY_paramgen(pctx, &params)) {
    goto error;
  }

  if (!(kctx = EVP_PKEY_CTX_new(params, NULL))) {
    goto error;
  }

  if (EVP_PKEY_keygen_init(kctx) != 1) {
    goto error;
  }

  if (EVP_PKEY_keygen(kctx, &pkey) != 1) {
    goto error;
  }

  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_CTX_free(kctx);
  EVP_PKEY_free(params);
  return pkey;

error:
  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_CTX_free(kctx);
  EVP_PKEY_free(params);
  return NULL;
}

int ecdh(EVP_PKEY *private_key, EVP_PKEY *public_key, unsigned char *out, size_t out_len, size_t *secret_len)
{
  EVP_PKEY_CTX *ctx = NULL;

  if (!(ctx = EVP_PKEY_CTX_new(private_key, NULL))) {
    goto error;
  }

  if (EVP_PKEY_derive_init(ctx) != 1) {
    goto error;
  }

  /* Provide the peer public EC key */
  if (EVP_PKEY_derive_set_peer(ctx, public_key) != 1) {
    goto error;
  }

  /* Determine buffer length for shared secret */
  if (EVP_PKEY_derive(ctx, NULL, secret_len) != 1) {
    goto error;
  }

  if (*secret_len > out_len) {
    goto error;
  }

  /* Derive the ECDH shared secret */
  if ((EVP_PKEY_derive(ctx, out, secret_len)) != 1) {
    goto error;
  }

  EVP_PKEY_CTX_free(ctx);
  return 0;

error:
  EVP_PKEY_CTX_free(ctx);
  return -1;
}

int generate_keymat(struct keymat *keymat, const unsigned char *shared_secret, size_t shared_secret_len, const unsigned char *nonce_a, size_t nonce_a_len, const unsigned char *nonce_b, size_t nonce_b_len)
{
  EVP_MAC *mac = NULL;
  EVP_MAC_CTX *ctx = NULL;

  const unsigned char extract_info[7] = "Extract";
  const unsigned char expand_info[6] = "Expand";

  unsigned char *keymat_ptr = (unsigned char*)keymat;
  unsigned char iter = 0x01;

  unsigned char extracted_key[AES_CMAC_BLOCK_SIZE];
  size_t extracted_key_len, key_len, blocksize, offset;

  OSSL_PARAM params[2];

  if (!(mac = EVP_MAC_fetch(NULL, "cmac", NULL))) {
    goto error;
  }

  params[0] = OSSL_PARAM_construct_utf8_string("cipher", "aes-128-cbc", 0);
  params[1] = OSSL_PARAM_construct_end();

  if (!(ctx = EVP_MAC_CTX_new(mac))) {
    goto error;
  }

  if (!EVP_MAC_init(ctx, nonce_a, nonce_a_len, params)) {
    goto error;
  }

  /* Sanity check for the blocksize of used AES-CMAC */
  if ((blocksize = EVP_MAC_CTX_get_block_size(ctx)) != AES_CMAC_BLOCK_SIZE) {
    goto error;
  }

  /* Key extraction starts here */

  if (!EVP_MAC_update(ctx, shared_secret, shared_secret_len)) {
    goto error;
  }

  if (!EVP_MAC_update(ctx, nonce_b, nonce_b_len)) {
    goto error;
  }

  if (!EVP_MAC_update(ctx, extract_info, sizeof(extract_info))) {
    goto error;
  }

  if (!EVP_MAC_final(ctx, extracted_key, &extracted_key_len, sizeof(extracted_key))) {
    goto error;
  }

  /* Key expansion starts here */

  for (offset = 0; offset < sizeof(*keymat); ++iter) {
    if (!EVP_MAC_init(ctx, extracted_key, extracted_key_len, params)) {
      goto error;
    }

    if (offset > 0) {
      /* Include the previous CMAC digest in the current input */
      if (!EVP_MAC_update(ctx, keymat_ptr + offset - blocksize, blocksize)) {
        goto error;
      }
    }

    if (!EVP_MAC_update(ctx, expand_info, sizeof(expand_info))) {
      goto error;
    }

    if (!EVP_MAC_update(ctx, &iter, sizeof(iter))) {
      goto error;
    }

    if (!EVP_MAC_final(ctx, keymat_ptr + offset, &key_len, blocksize)) {
      goto error;
    }

    offset += blocksize;
  }

  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  return 0;

error:
  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  return -1;
}

int calculate_mac(const unsigned char *in, size_t in_len, const unsigned char *key, size_t key_len, unsigned char *out, size_t out_len)
{
  EVP_MAC *mac = NULL;
  EVP_MAC_CTX *ctx = NULL;
  size_t mac_len;

  OSSL_PARAM params[2];

  if (!(mac = EVP_MAC_fetch(NULL, "cmac", NULL))) {
    goto error;
  }

  params[0] = OSSL_PARAM_construct_utf8_string("cipher", "aes-128-cbc", 0);
  params[1] = OSSL_PARAM_construct_end();

  if (!(ctx = EVP_MAC_CTX_new(mac))) {
    goto error;
  }

  if (!EVP_MAC_init(ctx, key, key_len, params)) {
    goto error;
  }

  /* Sanity check for the blocksize of used AES-CMAC */
  if ((EVP_MAC_CTX_get_block_size(ctx)) != AES_CMAC_BLOCK_SIZE) {
    goto error;
  }

  if (!EVP_MAC_update(ctx, in, in_len)) {
    goto error;
  }

  if (!EVP_MAC_final(ctx, out, &mac_len, out_len)) {
    goto error;
  }

  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  return 0;

error:
  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  return -1;
}
