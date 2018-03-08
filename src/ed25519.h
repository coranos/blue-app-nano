#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>
#include "nano_types.h"

void ed25519_publickey(const nano_private_key_t privateKey,
                       nano_public_key_t publicKey);

void ed25519_sign(const uint8_t *m, size_t mlen,
                  const nano_private_key_t privateKey,
                  const nano_public_key_t publicKey,
                  nano_signature_t signature);

int ed25519_sign_open(const uint8_t *m, size_t mlen,
                      const nano_public_key_t publicKey,
                      const nano_signature_t signature);

#endif // ED25519_H
