// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <getopt.h>
/*
#include <openenclave/internal/elf.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/properties.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/sgxsign.h>
#include <openenclave/internal/str.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
*/
#include "openenclave/corelibc/stdlib.h"
#include "openenclave/host.h"

#include "../host/sgx/enclave.h"
#include "openenclave/internal/crypto/cert.h"
#include "openenclave/internal/sgxcertextensions.h"

static const char _usage[] = "Usage: %s --cert CERTIFICATE_FILE\n"
                             "\n";

oe_result_t ParseSGXExtensions(
    oe_cert_t* cert,
    uint8_t* buffer,
    size_t* buffer_size,
    ParsedExtensionInfo* parsed_info);

oe_result_t oe_cert_read_pem(
    oe_cert_t* cert,
    const void* pem_data,
    size_t pem_size);

int pck_cert_inspector(const char* cert_path)
{
    int ret = 0;

    FILE* f = fopen(cert_path, "r");
    fseek(f, 0, SEEK_END);
    unsigned long cert_size = (unsigned long)ftell(f);
    fseek(f, 0, SEEK_SET); /* same as rewind(f); */

    char* cert_pem = malloc(cert_size + 1);
    fread(cert_pem, 1, cert_size, f);
    fclose(f);

    printf("Cert:\n%s\n\n\n", cert_pem);

    oe_cert_t pck_cert;
    oe_cert_read_pem(&pck_cert, cert_pem, cert_size + 1);

    ParsedExtensionInfo parsed_info;

    size_t buffer_size = 16384;
    uint8_t buffer[16384];
    oe_result_t result =
        ParseSGXExtensions(&pck_cert, buffer, &buffer_size, &parsed_info);
    if (result != OE_OK)
    {
        printf("Error calling ParseSGXExtensions\n");
    }

    //    printf("parsed_info = %x\n", &(void*)parsed_info);

    return ret;
}

int arg_handler(int argc, const char* argv[])
{
    int ret = 0;
    char* cert_path;

    const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"cert", required_argument, NULL, 'c'},
        {NULL, 0, NULL, 0},
    };
    const char short_options[] = "hc:";

    int c;
    do
    {
        c = getopt_long(
            argc, (char* const*)argv, short_options, long_options, NULL);
        if (c == -1)
        {
            // all the command-line options are parsed
            break;
        }

        switch (c)
        {
            case 'h':
                fprintf(stderr, _usage, argv[0]);
                goto done;
            case 'c':
                cert_path = optarg;
                break;
            default:
                // Invalid option
                ret = 1;
                goto done;
        }
    } while (1);

    if (!ret)
        ret = pck_cert_inspector(cert_path);

done:

    return ret;
}

int main(int argc, const char* argv[])
{
    int ret = 1;

    if (argc <= 2)
    {
        fprintf(stderr, _usage, argv[0]);
        exit(1);
    }

    ret = arg_handler(argc, argv);
    return ret;
}
