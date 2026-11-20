#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <sys/resource.h>
#endif
#include <gmssl/mem.h>
#include "extensions.h"
#include "keygen_bridge.h"

#define main gmssl_cli_main
#include GMSSL_CLI_SOURCE
#undef main

#define MAX_ARGUMENTS 256U
#define MAX_ARGUMENT_LENGTH 65536U
#define MAX_FRAME_BYTES 1048576U

static int read_u32(uint32_t *value)
{
    unsigned char b[4];
    if (fread(b, 1, sizeof(b), stdin) != sizeof(b)) return 0;
    *value = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
        | ((uint32_t)b[2] << 8) | b[3];
    return 1;
}

int main(int argc, char **argv)
{
    static const unsigned char magic[8] = {'G','M','R','U','N','0','0','1'};
    unsigned char received[8];
    char *arguments[MAX_ARGUMENTS + 2] = {0};
    char *owned[MAX_ARGUMENTS] = {0};
    size_t lengths[MAX_ARGUMENTS] = {0};
    uint32_t count = 0, total = 0, used = 0, i;
    int result = 64;
    (void)argv;
    if (argc != 1) goto invalid;
#ifndef _WIN32
    {
        struct rlimit limit = {0, 0};
        if (setrlimit(RLIMIT_CORE, &limit) != 0) goto invalid;
        limit.rlim_cur = limit.rlim_max = 310;
        if (setrlimit(RLIMIT_CPU, &limit) != 0) goto invalid;
        limit.rlim_cur = limit.rlim_max = 16U * 1024U * 1024U;
        if (setrlimit(RLIMIT_FSIZE, &limit) != 0) goto invalid;
#ifdef __linux__
        limit.rlim_cur = limit.rlim_max = (rlim_t)2U * 1024U * 1024U * 1024U;
        if (setrlimit(RLIMIT_AS, &limit) != 0) goto invalid;
#endif
        umask(0077);
    }
#endif
    if (fread(received, 1, sizeof(received), stdin) != sizeof(received)
        || memcmp(received, magic, sizeof(magic)) != 0
        || !read_u32(&count) || !read_u32(&total)
        || count == 0 || count > MAX_ARGUMENTS || total > MAX_FRAME_BYTES)
        goto invalid;
    arguments[0] = "gmssl";
    for (i = 0; i < count; i++) {
        uint32_t length;
        if (!read_u32(&length) || length > MAX_ARGUMENT_LENGTH
            || length > total - used) goto invalid;
        owned[i] = calloc((size_t)length + 1, 1);
        if (!owned[i]) goto invalid;
        lengths[i] = (size_t)length + 1;
        if (fread(owned[i], 1, length, stdin) != length
            || memchr(owned[i], 0, length)) goto invalid;
        arguments[i + 1] = owned[i];
        used += length;
    }
    if (used != total || arguments[1][0] == 0) goto invalid;
    result = gmssl_keygen_bridge_main((int)count + 1, arguments);
    if (result == -2) result = gmssl_extension_main((int)count + 1, arguments);
    if (result == -2) result = gmssl_cli_main((int)count + 1, arguments);
    goto cleanup;
invalid:
    fputs("runner: invalid execution frame\n", stderr);
cleanup:
    for (i = 0; i < MAX_ARGUMENTS; i++) {
        if (owned[i]) {
            gmssl_secure_clear(owned[i], lengths[i]);
            free(owned[i]);
        }
    }
    return result;
}
