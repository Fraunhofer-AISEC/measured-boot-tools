/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#else
#include <openssl/core_names.h>
#endif

#include "tpm2_alg_util.h"
#include "tpm2_openssl.h"

#define KEYEDHASH_MAX_SIZE 128
#define HMAC_MAX_SIZE      64


const EVP_MD *tpm2_openssl_md_from_tpmhalg(TPMI_ALG_HASH algorithm) {

    switch (algorithm) {
    case TPM2_ALG_SHA1:
        return EVP_sha1();
    case TPM2_ALG_SHA256:
        return EVP_sha256();
    case TPM2_ALG_SHA384:
        return EVP_sha384();
    case TPM2_ALG_SHA512:
        return EVP_sha512();
#if HAVE_EVP_SM3
	case TPM2_ALG_SM3_256:
		return EVP_sm3();
#endif
    default:
        return NULL;
    }
    /* no return, not possible */
}

bool tpm2_openssl_hash_compute_data(TPMI_ALG_HASH halg, BYTE *buffer,
        UINT16 length, TPM2B_DIGEST *digest) {

    bool result = false;

    const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(halg);
    if (!md) {
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        printf("%s", tpm2_openssl_get_err());
        return false;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        printf("%s", tpm2_openssl_get_err());
        goto out;
    }

    rc = EVP_DigestUpdate(mdctx, buffer, length);
    if (!rc) {
        printf("%s", tpm2_openssl_get_err());
        goto out;
    }

    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(mdctx, digest->buffer, &size);
    if (!rc) {
        printf("%s", tpm2_openssl_get_err());
        goto out;
    }

    digest->size = size;

    result = true;

out:
    EVP_MD_CTX_destroy(mdctx);
    return result;
}

bool tpm2_openssl_pcr_extend(TPMI_ALG_HASH halg, BYTE *pcr,
        const BYTE *data, UINT16 length) {

    bool result = false;

    const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(halg);
    if (!md) {
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        printf("%s", tpm2_openssl_get_err());
        return false;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        printf("%s", tpm2_openssl_get_err());
        goto out;
    }

    // extend operation is pcr = HASH(pcr + data)
    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestUpdate(mdctx, pcr, size);
    if (!rc) {
        printf("%s", tpm2_openssl_get_err());
        goto out;
    }

    rc = EVP_DigestUpdate(mdctx, data, length);
    if (!rc) {
        printf("%s", tpm2_openssl_get_err());
        goto out;
    }

    rc = EVP_DigestFinal_ex(mdctx, pcr, &size);
    if (!rc) {
        printf("%s", tpm2_openssl_get_err());
        goto out;
    }

    result = true;

out:
    EVP_MD_CTX_destroy(mdctx);
    return result;
}
