#include "ed25519.h"
#include "os.h"
#include "cx.h"

void ed25519_publickey(const nano_private_key_t privateKey,
                       nano_public_key_t publicKey) {
    cx_ecfp_private_key_t sdkPrivateKey;
    cx_ecfp_public_key_t sdkPublicKey;

    cx_ecfp_init_private_key(CX_CURVE_Ed25519,
        (uint8_t *)privateKey, sizeof(nano_private_key_t),
        &sdkPrivateKey);
    cx_ecfp_init_public_key(CX_CURVE_Ed25519, NULL, 0, &sdkPublicKey);

    cx_ecfp_generate_pair2(CX_CURVE_Ed25519, &sdkPublicKey, &sdkPrivateKey, true, CX_BLAKE2B);
    os_memset(&sdkPrivateKey, 0, sizeof(sdkPrivateKey));

    cx_edward_compress_point(CX_CURVE_Ed25519, sdkPublicKey.W);
    os_memmove(publicKey, sdkPublicKey.W+1, sizeof(nano_public_key_t));
}

void ed25519_sign(const uint8_t *m, size_t mlen,
                  const nano_private_key_t privateKey,
                  const nano_public_key_t publicKey,
                  nano_signature_t signature) {
    cx_ecfp_private_key_t sdkPrivateKey;
    cx_ecfp_init_private_key(CX_CURVE_Ed25519,
        (uint8_t *)privateKey, sizeof(nano_private_key_t),
        &sdkPrivateKey);

    cx_eddsa_sign(
        &sdkPrivateKey,
        0, CX_BLAKE2B,
        (uint8_t *)m, mlen,
        NULL, 0,
        signature,
        0);
    os_memset(&sdkPrivateKey, 0, sizeof(sdkPrivateKey));
}

int ed25519_sign_open(const uint8_t *m, size_t mlen,
                      const nano_public_key_t publicKey,
                      const nano_signature_t signature) {
    cx_ecfp_public_key_t sdkPublicKey;
    cx_ecfp_init_public_key(CX_CURVE_Ed25519, NULL, 0, &sdkPublicKey);

    sdkPublicKey.W[0] = 0x02;
    os_memmove(sdkPublicKey.W+1, publicKey, sizeof(nano_public_key_t));
    cx_edward_decompress_point(CX_CURVE_Ed25519, sdkPublicKey.W);
    sdkPublicKey.W_len = 65;

    return cx_eddsa_verify(
        &sdkPublicKey,
        0, CX_BLAKE2B,
        (uint8_t *)m, mlen,
        NULL, 0,
        (uint8_t *)signature, sizeof(nano_signature_t));
}
