#ifndef MESSAGE_H
#define MESSAGE_H

#include <inttypes.h>

/* MESSAGE TYPE DEFINITIONS */

#define MSG_TYPE_FIRST    0x01
#define MSG_TYPE_SECOND   0x02
#define MSG_TYPE_THIRD    0x03
#define MSG_TYPE_FOURTH   0x04

/* DEFINITIONS FOR MESSAGE FIELD SIZES */

#define SIZE_PUBKEY    129  /* Size of EC public key field (bytes) */
#define SIZE_NONCE      16  /* Size of nonce field (bytes)         */
#define SIZE_MAC        16  /* Size of MAC field (bytes)           */

#pragma pack(push,1)

struct MSG_FIRST {
  uint16_t type;
  uint16_t curve;
};

struct MSG_SECOND {
  uint16_t type;
  uint16_t curve;
  uint16_t pubkey_len;
  uint8_t pubkey[SIZE_PUBKEY];
  uint8_t nonce_a[SIZE_NONCE];
};

struct MSG_THIRD {
  uint16_t type;
  uint16_t pubkey_len;
  uint8_t pubkey[SIZE_PUBKEY];
  uint8_t nonce_a[SIZE_NONCE];
  uint8_t nonce_b[SIZE_NONCE];
  uint8_t mac[SIZE_MAC];
};

struct MSG_FOURTH {
  uint16_t type;
  uint8_t nonce_b[SIZE_NONCE];
  uint8_t mac[SIZE_MAC];
};

#pragma pack(pop)

#endif
