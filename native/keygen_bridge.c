/*
 * Key generation bridge for converting unencrypted PKCS#8 DER keys (e.g. from OpenSSL)
 * into GmSSL-compatible encrypted PKCS#8 PEM and public key PEM files.
 *
 * This bridge is an internal command in gmssl-runner ("__keygen_bridge") invoked exclusively
 * via GMRUN001 frame stdin from engine-service, ensuring passphrases are never passed
 * via argv or environment variables.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/x509_key.h>
#include <gmssl/file.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>
#include "keygen_bridge.h"

int gmssl_keygen_bridge_main(int argc, char **argv)
{
    int ret = 1;
    char *prog;
    char *infile = NULL;
    char *outfile = NULL;
    char *puboutfile = NULL;
    char *pass = NULL;
    FILE *outfp = NULL;
    FILE *puboutfp = NULL;
    uint8_t *der = NULL;
    size_t der_len = 0;
    const uint8_t *cp;
    size_t inlen;
    const uint8_t *attrs = NULL;
    size_t attrslen = 0;
    X509_KEY key;
    int key_initialized = 0;

    if (argc < 2 || strcmp(argv[1], "__keygen_bridge") != 0) {
        return -2; /* Not handled by this bridge */
    }

    prog = argv[1];
    argc -= 2;
    argv += 2;

    while (argc > 0) {
        if (!strcmp(*argv, "-help")) {
            fprintf(stdout, "usage: gmssl __keygen_bridge -in <der> -out <pem> [-pubout <pem>] -pass <passphrase>\n");
            return 0;
        } else if (!strcmp(*argv, "-in")) {
            if (--argc < 1) goto bad;
            infile = *(++argv);
        } else if (!strcmp(*argv, "-out")) {
            if (--argc < 1) goto bad;
            outfile = *(++argv);
        } else if (!strcmp(*argv, "-pubout")) {
            if (--argc < 1) goto bad;
            puboutfile = *(++argv);
        } else if (!strcmp(*argv, "-pass")) {
            if (--argc < 1) goto bad;
            pass = *(++argv);
        } else {
            fprintf(stderr, "gmssl %s: illegal option '%s'\n", prog, *argv);
            goto end;
bad:
            fprintf(stderr, "gmssl %s: '%s' option value missing\n", prog, *argv);
            goto end;
        }
        argc--;
        argv++;
    }

    if (!infile) {
        fprintf(stderr, "gmssl %s: '-in' option required\n", prog);
        goto end;
    }
    if (!outfile) {
        fprintf(stderr, "gmssl %s: '-out' option required\n", prog);
        goto end;
    }
    if (!pass) {
        fprintf(stderr, "gmssl %s: '-pass' option required\n", prog);
        goto end;
    }

    if (file_read_all(infile, &der, &der_len) != 1) {
        fprintf(stderr, "gmssl %s: failed to read input file '%s'\n", prog, infile);
        goto end;
    }

    memset(&key, 0, sizeof(key));
    key_initialized = 1;
    cp = der;
    inlen = der_len;

    if (x509_private_key_info_from_der(&key, &attrs, &attrslen, &cp, &inlen) != 1 || inlen != 0) {
        fprintf(stderr, "gmssl %s: failed to parse unencrypted PKCS#8 DER private key\n", prog);
        goto end;
    }

    outfp = fopen(outfile, "wb");
    if (!outfp) {
        fprintf(stderr, "gmssl %s: failed to open output file '%s'\n", prog, outfile);
        goto end;
    }

    if (x509_private_key_info_encrypt_to_pem(&key, pass, outfp) != 1) {
        fprintf(stderr, "gmssl %s: failed to encrypt private key to PEM\n", prog);
        goto end;
    }
    fflush(outfp);

    if (puboutfile) {
        puboutfp = fopen(puboutfile, "wb");
        if (!puboutfp) {
            fprintf(stderr, "gmssl %s: failed to open pubout file '%s'\n", prog, puboutfile);
            goto end;
        }
        if (x509_public_key_info_to_pem(&key, puboutfp) != 1) {
            fprintf(stderr, "gmssl %s: failed to write public key to PEM\n", prog);
            goto end;
        }
        fflush(puboutfp);
    }

    ret = 0;

end:
    if (key_initialized) {
        gmssl_secure_clear(&key, sizeof(key));
    }
    if (der) {
        gmssl_secure_clear(der, der_len);
        free(der);
    }
    if (outfp) {
        fclose(outfp);
    }
    if (puboutfp) {
        fclose(puboutfp);
    }
    return ret;
}
