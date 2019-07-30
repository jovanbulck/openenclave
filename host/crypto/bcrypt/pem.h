// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_PEM_H
#define _OE_HOST_CRYPTO_PEM_H

#include <Windows.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

oe_result_t oe_bcrypt_pem_to_der(
    const uint8_t* pem_data,
    size_t pem_size,
    BYTE** der_data,
    DWORD* der_size);

oe_result_t oe_bcrypt_der_to_pem(
    const BYTE* der_data,
    DWORD der_size,
    uint8_t** pem_data,
    size_t* pem_size);

oe_result_t oe_get_next_pem_cert(
    const void** pem_read_pos,
    size_t* pem_bytes_remaining,
    char** pem_cert,
    size_t* pem_cert_size);

#endif /* _OE_HOST_CRYPTO_PEM_H */
