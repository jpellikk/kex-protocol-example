#ifndef HELPER_H
#define HELPER_H

#include "crypto.h"
#include <stdio.h>

void print_ecdh_key(FILE *fp, const unsigned char *key, size_t key_len);
void print_keymat(FILE *fp, const struct keymat *keymat);

#endif
