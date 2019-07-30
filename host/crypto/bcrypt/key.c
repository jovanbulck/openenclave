// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "key.h"
#include <assert.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/pem.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include "bcrypt.h"
#include "pem.h"

/* Caller is responsible for calling BCryptDestroyKey on handle */
oe_result_t oe_bcrypt_decode_x509_public_key(
    const BYTE* der_data,
    DWORD der_data_size,
    BCRYPT_KEY_HANDLE* handle)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* key_blob = NULL;
    DWORD key_blob_size = 0;

    /* Decode DER data as an X509 public key property */
    BOOL success = CryptDecodeObjectEx(
        X509_ASN_ENCODING,
        X509_PUBLIC_KEY_INFO,
        der_data,
        der_data_size,
        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
        NULL,
        &key_blob,
        &key_blob_size);

    if (!success)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CryptDecodeObjectEx failed (err=%#x)\n",
            GetLastError());
    {
        /* Import the X509 public key */
        PCERT_PUBLIC_KEY_INFO keyinfo = (PCERT_PUBLIC_KEY_INFO)key_blob;

        success = CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING, keyinfo, 0, NULL, handle);

        if (!success)
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CryptImportPublicKeyInfo2 failed (err=%#x)\n",
                GetLastError());
    }

    result = OE_OK;

done:
    return result;
}

/* Caller is responsible for calling LocalFree on der_data */
oe_result_t oe_bcrypt_encode_x509_public_key(
    const BCRYPT_KEY_HANDLE handle,
    LPSTR key_oid,
    BYTE** der_data,
    DWORD* der_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* key_blob = NULL;
    DWORD key_blob_size = 0;
    PCERT_PUBLIC_KEY_INFO keyinfo = NULL;

    /* Export the public keyinfo from the BCrypt key handle */
    OE_CHECK(oe_bcrypt_get_public_key_info(handle, key_oid, &keyinfo));

    {
        /* Encode the keyinfo structure as a X509 public key */
        BOOL success = CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            keyinfo,
            CRYPT_ENCODE_ALLOC_FLAG,
            NULL,
            der_data,
            der_data_size);

        if (!success)
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CryptEncodeObjectEx failed (err=%#x)\n",
                GetLastError());
    }

    result = OE_OK;

done:
    if (keyinfo)
        free(keyinfo);

    return result;
}

/* Caller is responsible for calling free on key_blob_data */
oe_result_t oe_bcrypt_export_key(
    const BCRYPT_KEY_HANDLE handle,
    LPCWSTR key_blob_type,
    BYTE** key_blob_data,
    ULONG* key_blob_size)
{
    oe_result_t result = OE_UNEXPECTED;
    BYTE* export_data = NULL;
    ULONG export_size = 0;
    ULONG output_size = 0;

    NTSTATUS status =
        BCryptExportKey(handle, NULL, key_blob_type, NULL, 0, &export_size, 0);
    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptExportKey failed, err=%#x\n", status);

    export_data = malloc(export_size);
    if (!export_data)
        OE_RAISE(OE_OUT_OF_MEMORY);

    status = BCryptExportKey(
        handle, NULL, key_blob_type, export_data, export_size, &output_size, 0);
    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptExportKey failed, err=%#x\n", status);

    if (output_size != export_size)
        OE_RAISE_MSG(
            OE_UNEXPECTED,
            "BCryptExportKey wrote:%#x bytes, expected:%#x bytes\n",
            output_size,
            export_size);

    *key_blob_size = export_size;
    *key_blob_data = export_data;
    export_data = NULL;

    result = OE_OK;

done:
    if (export_data)
        free(export_data);

    return result;
}

/* Caller is responsible for calling free on keyinfo. */
oe_result_t oe_bcrypt_get_public_key_info(
    const BCRYPT_KEY_HANDLE handle,
    LPSTR key_oid,
    PCERT_PUBLIC_KEY_INFO* keyinfo)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* keyinfo_data = NULL;
    DWORD keyinfo_size = 0;

    BOOL success = CryptExportPublicKeyInfoFromBCryptKeyHandle(
        handle,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        key_oid,
        0,
        NULL,
        NULL,
        &keyinfo_size);

    /* Should return true and set keyinfo_size when given a null buffer */
    if (!success)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CryptExportPublicKeyInfoFromBCryptKeyHandle failed (err=%#x)\n",
            GetLastError());

    keyinfo_data = (uint8_t*)malloc(keyinfo_size);
    if (keyinfo_data == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    success = CryptExportPublicKeyInfoFromBCryptKeyHandle(
        handle,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        key_oid,
        0,
        NULL,
        (PCERT_PUBLIC_KEY_INFO)keyinfo_data,
        &keyinfo_size);

    if (!success)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CryptExportPublicKeyInfoFromBCryptKeyHandle failed (err=%#x)\n",
            GetLastError());

    *keyinfo = (PCERT_PUBLIC_KEY_INFO)keyinfo_data;
    keyinfo_data = NULL;
    result = OE_OK;

done:
    if (keyinfo_data)
        free(keyinfo_data);

    return result;
}

oe_result_t oe_bcrypt_key_free(oe_bcrypt_key_t* key, uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (key)
    {
        /* Check parameter */
        if (!oe_bcrypt_key_is_valid(key, magic))
            OE_RAISE(OE_INVALID_PARAMETER);

        /* Release the key */
        BCryptDestroyKey(key->pkey);

        /* Clear the fields of the implementation */
        oe_secure_zero_fill(key, sizeof(*key));
    }

    result = OE_OK;

done:
    return result;
}

void oe_bcrypt_key_init(
    oe_bcrypt_key_t* key,
    BCRYPT_KEY_HANDLE* pkey,
    uint64_t magic)
{
    key->magic = magic;
    key->pkey = pkey;
}

bool oe_bcrypt_key_is_valid(const oe_bcrypt_key_t* impl, uint64_t magic)
{
    return impl && impl->magic == magic && impl->pkey;
}

/* Caller is expected to call free on blob_data */
oe_result_t oe_bcrypt_key_get_blob(
    const oe_bcrypt_key_t* key,
    uint64_t magic,
    LPCWSTR blob_type,
    BYTE** blob_data,
    ULONG* blob_size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (blob_data)
        *blob_data = NULL;

    if (blob_size)
        *blob_size = 0;

    /* Check parameter */
    if (!oe_bcrypt_key_is_valid(key, magic))
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_bcrypt_export_key(key->pkey, blob_type, blob_data, blob_size));

    result = OE_OK;

done:
    return result;
}

/* Caller is responsible for calling oe_bcrypt_key_free on key */
oe_result_t oe_bcrypt_key_read_pem(
    const uint8_t* pem_data,
    size_t pem_size,
    uint64_t key_magic,
    oe_bcrypt_decode_key_callback_t decode_key,
    oe_bcrypt_key_t* key)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* der_data = NULL;
    DWORD der_size = 0;
    BCRYPT_KEY_HANDLE handle = NULL;

    /* Zero-initialize the key */
    if (key)
        oe_secure_zero_fill(key, sizeof(oe_bcrypt_key_t));

    /* Check parameters */
    if (!pem_data || !pem_size || pem_size > OE_INT_MAX || !key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Convert PEM to DER. */
    OE_CHECK(oe_bcrypt_pem_to_der(pem_data, pem_size, &der_data, &der_size));

    /* Decode the DER into a BCrypt key handle */
    OE_CHECK(decode_key(der_data, der_size, &handle));

    /* Wrap BCrypt key handle as oe_bcrypt_key_t. */
    oe_bcrypt_key_init(key, handle, key_magic);
    handle = NULL;

    result = OE_OK;

done:
    if (handle)
        BCryptDestroyKey(handle);

    if (der_data)
    {
        oe_secure_zero_fill(der_data, der_size);
        free(der_data);
        der_size = 0;
    }

    return result;
}

oe_result_t oe_bcrypt_key_write_pem(
    const oe_bcrypt_key_t* key,
    uint64_t key_magic,
    oe_bcrypt_encode_key_callback_t encode_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* der_blob = NULL;
    DWORD der_blob_size = 0;
    uint8_t* pem_blob = NULL;
    size_t pem_blob_size = 0;

    /* Check parameters */
    if (!oe_bcrypt_key_is_valid(key, key_magic) || !pem_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pem_data && *pem_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Encode the BCrypt key handles into DER format */
    OE_CHECK(encode_key(key->pkey, &der_blob, &der_blob_size));

    /* Convert DER to PEM. */
    OE_CHECK(oe_bcrypt_der_to_pem(
        der_blob, der_blob_size, &pem_blob, &pem_blob_size));

    /* Check buffer size and populate required size */
    if (*pem_size < pem_blob_size)
    {
        *pem_size = pem_blob_size;
        OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
    }

    /* Copy result to output buffer */
    OE_CHECK(oe_memcpy_s(pem_data, *pem_size, pem_blob, pem_blob_size));
    *pem_size = pem_blob_size;

    result = OE_OK;

done:
    if (pem_blob)
    {
        oe_secure_zero_fill(pem_blob, pem_blob_size);
        free(pem_blob);
        pem_blob_size = 0;
    }

    if (der_blob)
    {
        oe_secure_zero_fill(der_blob, der_blob_size);
        LocalFree(der_blob);
        der_blob_size = 0;
    }

    return result;
}

oe_result_t oe_private_key_sign(
    const oe_private_key_t* private_key,
    const oe_bcrypt_padding_info_t* padding_info,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_bcrypt_key_t* impl = (const oe_bcrypt_key_t*)private_key;
    const oe_bcrypt_padding_info_t default_padding_info = {0};
    ULONG sig_size = 0;
    NTSTATUS status;

    if (!padding_info)
        padding_info = &default_padding_info;

    /* Check for null parameters and invalid sizes. */
    if (!oe_bcrypt_key_is_valid(impl, magic) || !hash_data || !hash_size ||
        hash_size > MAXDWORD || !signature_size || *signature_size > MAXDWORD)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signature_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Determine the size of the signature; fail if buffer is too small */
    status = BCryptSignHash(
        impl->pkey,
        padding_info->config,
        (PUCHAR)hash_data,
        (ULONG)hash_size,
        NULL,
        0,
        &sig_size,
        padding_info->type);

    if (!BCRYPT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptSignHash failed (err=%#x)\n", status);

    if (sig_size > *signature_size)
    {
        *signature_size = sig_size;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    status = BCryptSignHash(
        impl->pkey,
        padding_info->config,
        (PUCHAR)hash_data,
        (ULONG)hash_size,
        signature,
        sig_size,
        &sig_size,
        padding_info->type);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptSignHash failed (err=%#x)\n", status);

    *signature_size = sig_size;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_public_key_verify(
    const oe_public_key_t* public_key,
    const oe_bcrypt_padding_info_t* padding_info,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_bcrypt_key_t* impl = (const oe_bcrypt_key_t*)public_key;
    const oe_bcrypt_padding_info_t default_padding_info = {0};
    NTSTATUS status;

    /* Check parameters */
    if (!oe_bcrypt_key_is_valid(impl, magic) || !hash_data || !hash_size ||
        hash_size > MAXDWORD || !signature || !signature_size ||
        signature_size > MAXDWORD)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    if (!padding_info)
        padding_info = &default_padding_info;

    status = BCryptVerifySignature(
        impl->pkey,
        padding_info->config,
        (PUCHAR)hash_data,
        (ULONG)hash_size,
        (PUCHAR)signature,
        (ULONG)signature_size,
        padding_info->type);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "BCryptVerifySignature failed (err=%#x)\n",
            status);

    result = OE_OK;

done:
    return result;
}
