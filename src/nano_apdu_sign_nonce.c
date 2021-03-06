/*******************************************************************************
*   $NANO Wallet for Ledger Nano S & Blue
*   (c) 2018 Mart Roosmaa
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "nano_internal.h"
#include "nano_apdu_constants.h"
#include "nano_apdu_sign_nonce.h"

#define P1_UNUSED 0x00
#define P2_UNUSED 0x00

uint16_t nano_apdu_sign_nonce_output(nano_apdu_response_t *resp, nano_apdu_sign_nonce_request_t *req);

uint16_t nano_apdu_sign_nonce(nano_apdu_response_t *resp) {
    nano_apdu_sign_nonce_request_t *req = &ram_a.nano_apdu_sign_nonce_heap_D.req;
    uint8_t *inPtr;
    uint8_t readLen;

    switch (G_io_apdu_buffer[ISO_OFFSET_P1]) {
    case P1_UNUSED:
        break;
    default:
        return NANO_SW_INCORRECT_P1_P2;
    }

    switch (G_io_apdu_buffer[ISO_OFFSET_P2]) {
    case P2_UNUSED:
        break;
    default:
        return NANO_SW_INCORRECT_P1_P2;
    }

    // Verify the minimum size
    if (G_io_apdu_buffer[ISO_OFFSET_LC] < 17) {
        return NANO_SW_INCORRECT_LENGTH;
    }

    inPtr = G_io_apdu_buffer + ISO_OFFSET_CDATA;
    readLen = 1 + (*inPtr) * 4;
    os_memmove(req->keyPath, inPtr, MIN(readLen, sizeof(req->keyPath)));
    inPtr += readLen;

    if (!os_global_pin_is_validated()) {
        return NANO_SW_SECURITY_STATUS_NOT_SATISFIED;
    }

    readLen = sizeof(req->nonce);
    os_memmove(req->nonce, inPtr, readLen);
    inPtr += readLen;

    uint16_t statusWord = nano_apdu_sign_nonce_output(resp, req);
    os_memset(req, 0, sizeof(*req)); // sanitise request data
    return statusWord;
}

uint16_t nano_apdu_sign_nonce_output(nano_apdu_response_t *resp, nano_apdu_sign_nonce_request_t *req) {
    nano_apdu_sign_nonce_heap_output_t *h = &ram_a.nano_apdu_sign_nonce_heap_D.io.output;
    uint8_t *outPtr = resp->buffer;

    // Derive key and sign the block
    nano_derive_keypair(req->keyPath, h->privateKey, h->publicKey);
    nano_sign_nonce(h->signature, req->nonce, h->privateKey, h->publicKey);
    os_memset(h->privateKey, 0, sizeof(h->privateKey));

    // Output signature
    os_memmove(outPtr, h->signature, sizeof(h->signature));
    outPtr += sizeof(h->signature);

    resp->outLength = outPtr - resp->buffer;

    return NANO_SW_OK;
}
