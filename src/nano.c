/*******************************************************************************
*   $NANO Wallet for Ledger Nano S & Blue
*   (c) 2016 Ledger
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

#include "os.h"
#include "os_io_seproxyhal.h"

#include "nano_internal.h"
#include "nano_apdu_constants.h"

#ifdef HAVE_U2F

#include "u2f_service.h"
#include "u2f_transport.h"

extern bool fidoActivated;
extern volatile u2f_service_t u2fService;
void u2f_proxy_response(u2f_service_t *service, uint16_t tx);

#endif

void app_dispatch(void) {
    uint8_t cla;
    uint8_t ins;
    uint8_t dispatched;

    // nothing to reply for now
    nano_context_D.outLength = 0;
    nano_context_D.ioFlags = 0;

    BEGIN_TRY {
        TRY {
            // If halted, then notify
            SB_CHECK(nano_context_D.halted);
            if (SB_GET(nano_context_D.halted)) {
                nano_context_D.sw = NANO_SW_HALTED;
                goto sendSW;
            }

            cla = G_io_apdu_buffer[ISO_OFFSET_CLA];
            ins = G_io_apdu_buffer[ISO_OFFSET_INS];
            for (dispatched = 0; dispatched < DISPATCHER_APDUS; dispatched++) {
                if ((cla == DISPATCHER_CLA[dispatched]) &&
                    (ins == DISPATCHER_INS[dispatched])) {
                    break;
                }
            }
            if (dispatched == DISPATCHER_APDUS) {
                nano_context_D.sw = NANO_SW_INS_NOT_SUPPORTED;
                goto sendSW;
            }
            if (DISPATCHER_DATA_IN[dispatched]) {
                if (G_io_apdu_buffer[ISO_OFFSET_LC] == 0x00 ||
                    nano_context_D.inLength - 5 == 0) {
                    nano_context_D.sw = NANO_SW_INCORRECT_LENGTH;
                    goto sendSW;
                }
                // notify we need to receive data
                // io_exchange(CHANNEL_APDU | IO_RECEIVE_DATA, 0);
            }
            // call the apdu handler
            nano_context_D.sw = ((apduProcessingFunction)PIC(
                DISPATCHER_FUNCTIONS[dispatched]))();

        sendSW:
            // prepare SW after replied data
            G_io_apdu_buffer[nano_context_D.outLength] =
                (nano_context_D.sw >> 8);
            G_io_apdu_buffer[nano_context_D.outLength + 1] =
                (nano_context_D.sw & 0xff);
            nano_context_D.outLength += 2;
        }
        CATCH(EXCEPTION_IO_RESET) {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e) {
            // uncaught exception detected
            G_io_apdu_buffer[0] = 0x6F;
            nano_context_D.outLength = 2;
            G_io_apdu_buffer[1] = e;
            // we caught something suspicious
            SB_SET(nano_context_D.halted, 1);
        }
        FINALLY;
    }
    END_TRY;
}

void app_async_response(void) {
    G_io_apdu_buffer[nano_context_D.outLength] =
        (nano_context_D.sw >> 8);
    G_io_apdu_buffer[nano_context_D.outLength + 1] =
        (nano_context_D.sw & 0xff);
    nano_context_D.outLength += 2;

#ifdef HAVE_U2F
    if (fidoActivated) {
        u2f_proxy_response((u2f_service_t *)&u2fService,
            nano_context_D.outLength);
    } else {
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX,
            nano_context_D.outLength);
    }
#else
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX,
        nano_context_D.outLength);
#endif
}

void app_main(void) {
    os_memset(G_io_apdu_buffer, 0, 255); // paranoia

    // Process the incoming APDUs

    // first exchange, no out length :) only wait the apdu
    nano_context_D.outLength = 0;
    nano_context_D.ioFlags = 0;
    for (;;) {
        L_DEBUG_APP(("Main Loop\n"));

        // os_memset(G_io_apdu_buffer, 0, 255); // paranoia

        // receive the whole apdu using the 7 bytes headers (ledger transport)
        nano_context_D.inLength =
            io_exchange(CHANNEL_APDU | nano_context_D.ioFlags,
                        // use the previous outlength as the reply
                        nano_context_D.outLength);

        app_dispatch();

        // reply during reception of next apdu
    }

    L_DEBUG_APP(("End of main loop\n"));

    // in case reached
    reset();
}