// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/trace.h>
#include "enclave.h"

/*
 * This file is separated from traceh.c since the host verification library
 * should not depend on ECALLS.
 */
oe_result_t oe_log_enclave_init(oe_enclave_t* enclave)
{
    initialize_log_config();

    return oe_log_init_ecall(enclave, enclave->path, _log_level);
}
