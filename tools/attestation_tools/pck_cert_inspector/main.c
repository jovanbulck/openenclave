// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <getopt.h>
#include "openenclave/corelibc/stdlib.h"
#include "openenclave/host.h"
#include "openenclave/internal/crypto/cert.h"
#include "openenclave/internal/defs.h"
#include "openenclave/internal/hexdump.h"
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
    fseek(f, 0, SEEK_SET);

    char* cert_pem = malloc(cert_size + 1);
    fread(cert_pem, 1, cert_size, f);
    fclose(f);

    oe_cert_t pck_cert;
    oe_cert_read_pem(&pck_cert, cert_pem, cert_size + 1);

    ParsedExtensionInfo parsed_info;

    size_t buffer_size = 16384;
    uint8_t buffer[16384];
    oe_result_t result =
        ParseSGXExtensions(&pck_cert, buffer, &buffer_size, &parsed_info);
    if (result != OE_OK)
    {
        printf("Error: Unable to parse TCB info in certificate.\n");
    }

    // Use openssl's CLI to print out standard certificate info.
    size_t cmd_to_run_maxlength = 4096;
    char* cmd_to_run = calloc(1, cmd_to_run_maxlength);
    snprintf(
        cmd_to_run,
        cmd_to_run_maxlength - 1,
        "openssl x509 -in %s -text -noout",
        cert_path);
    system(cmd_to_run);
    printf("\n");

    printf("Extracted TCB values (displayed in hexadecimal):\n");

    printf("ppid                 = ");
    for (size_t count = 0; count < OE_FIELD_SIZE(ParsedExtensionInfo, ppid);
         ++count)
    {
        printf("%02x ", parsed_info.ppid[count]);
    }
    printf("\n");

    printf("comp_svn             = ");
    for (size_t count = 0; count < OE_FIELD_SIZE(ParsedExtensionInfo, comp_svn);
         ++count)
    {
        printf("%02x ", parsed_info.comp_svn[count]);
    }
    printf("\n");

    printf("pce_svn              = ");
    printf("%04x", parsed_info.pce_svn);
    printf("\n");

    printf("cpu_svn              = ");
    for (size_t count = 0; count < OE_FIELD_SIZE(ParsedExtensionInfo, cpu_svn);
         ++count)
    {
        printf("%02x ", parsed_info.cpu_svn[count]);
    }
    printf("\n");

    printf("pce_id               = ");
    for (size_t count = 0; count < OE_FIELD_SIZE(ParsedExtensionInfo, pce_id);
         ++count)
    {
        printf("%02x ", parsed_info.pce_id[count]);
    }
    printf("\n");

    printf("fmspc                = ");
    for (size_t count = 0; count < OE_FIELD_SIZE(ParsedExtensionInfo, fmspc);
         ++count)
    {
        printf("%02x ", parsed_info.fmspc[count]);
    }
    printf("\n");

    printf("sgx_type             = ");
    printf("%02x", parsed_info.sgx_type);
    printf("\n");

    printf("opt_dynamic_platform = ");
    printf("%d", parsed_info.opt_dynamic_platform);
    printf("\n");

    printf("opt_cached_keys      = ");
    printf("%d", parsed_info.opt_cached_keys);
    printf("\n");

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

    if (argc <= 1)
    {
        fprintf(stderr, _usage, argv[0]);
        exit(1);
    }

    ret = arg_handler(argc, argv);
    return ret;
}
