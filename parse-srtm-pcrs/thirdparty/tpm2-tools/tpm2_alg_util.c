/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "common.h"
#include "tpm2_alg_util.h"

typedef struct alg_pair alg_pair;
struct alg_pair {
    const char *name;
    TPM2_ALG_ID id;
    tpm2_alg_util_flags flags;
    tpm2_alg_util_flags _flags;
};

typedef enum alg_iter_res alg_iter_res;
enum alg_iter_res {
    stop,
    go,
    found
};

typedef enum alg_parser_rc alg_parser_rc;
enum alg_parser_rc {
    alg_parser_rc_error,
    alg_parser_rc_continue,
    alg_parser_rc_done
};

typedef alg_iter_res (*alg_iter)(TPM2_ALG_ID id, const char *name,
        tpm2_alg_util_flags flags, void *userdata);

static void tpm2_alg_util_for_each_alg(alg_iter iterator, void *userdata) {

    static const alg_pair algs[] = {

        // Asymmetric
        { .name = "rsa", .id = TPM2_ALG_RSA, .flags = tpm2_alg_util_flags_asymmetric|tpm2_alg_util_flags_base },
        { .name = "ecc", .id = TPM2_ALG_ECC, .flags = tpm2_alg_util_flags_asymmetric|tpm2_alg_util_flags_base },

        // Symmetric
        { .name = "tdes", .id = TPM2_ALG_TDES, .flags = tpm2_alg_util_flags_symmetric },
        { .name = "aes", .id = TPM2_ALG_AES, .flags = tpm2_alg_util_flags_symmetric },
        { .name = "camellia", .id = TPM2_ALG_CAMELLIA, .flags = tpm2_alg_util_flags_symmetric },
        { .name = "sm4", .id = TPM2_ALG_SM4, .flags = tpm2_alg_util_flags_symmetric },

        // Hash
        { .name = "sha1", .id = TPM2_ALG_SHA1, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha256", .id = TPM2_ALG_SHA256, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha384", .id = TPM2_ALG_SHA384, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha512", .id = TPM2_ALG_SHA512, .flags = tpm2_alg_util_flags_hash },
        { .name = "sm3_256", .id = TPM2_ALG_SM3_256, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha3_256", .id = TPM2_ALG_SHA3_256, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha3_384", .id = TPM2_ALG_SHA3_384, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha3_512", .id = TPM2_ALG_SHA3_512, .flags = tpm2_alg_util_flags_hash },

        // Keyed hash
        { .name = "hmac", .id = TPM2_ALG_HMAC, tpm2_alg_util_flags_keyedhash | tpm2_alg_util_flags_sig },
        { .name = "xor", .id = TPM2_ALG_XOR, tpm2_alg_util_flags_keyedhash },
        { .name = "cmac", .id = TPM2_ALG_CMAC, .flags = tpm2_alg_util_flags_sig },

        // Mask Generation Functions
        { .name = "mgf1", .id = TPM2_ALG_MGF1, .flags = tpm2_alg_util_flags_mgf },

        // Signature Schemes
        { .name = "rsassa", .id = TPM2_ALG_RSASSA, .flags = tpm2_alg_util_flags_sig },
        { .name = "rsapss", .id = TPM2_ALG_RSAPSS, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecdsa", .id = TPM2_ALG_ECDSA, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecdaa", .id = TPM2_ALG_ECDAA, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecschnorr", .id = TPM2_ALG_ECSCHNORR, .flags = tpm2_alg_util_flags_sig },
        { .name = "sm2", .id = TPM2_ALG_SM2, .flags = tpm2_alg_util_flags_sig },

        // Asymmetric Encryption Scheme
        { .name = "oaep", .id = TPM2_ALG_OAEP, .flags = tpm2_alg_util_flags_enc_scheme | tpm2_alg_util_flags_rsa_scheme },
        { .name = "rsaes", .id = TPM2_ALG_RSAES, .flags = tpm2_alg_util_flags_enc_scheme | tpm2_alg_util_flags_rsa_scheme },
        { .name = "ecdh", .id = TPM2_ALG_ECDH, .flags = tpm2_alg_util_flags_enc_scheme },

        // Key derivation functions
        { .name = "kdf1_sp800_56a", .id = TPM2_ALG_KDF1_SP800_56A, .flags = tpm2_alg_util_flags_kdf },
        { .name = "kdf2", .id = TPM2_ALG_KDF2, .flags = tpm2_alg_util_flags_kdf },
        { .name = "kdf1_sp800_108", .id = TPM2_ALG_KDF1_SP800_108, .flags = tpm2_alg_util_flags_kdf },
        { .name = "ecmqv", .id = TPM2_ALG_ECMQV, .flags = tpm2_alg_util_flags_kdf },

        // Modes
        { .name = "ctr", .id = TPM2_ALG_CTR, .flags = tpm2_alg_util_flags_mode },
        { .name = "ofb", .id = TPM2_ALG_OFB, .flags = tpm2_alg_util_flags_mode },
        { .name = "cbc", .id = TPM2_ALG_CBC, .flags = tpm2_alg_util_flags_mode },
        { .name = "cfb", .id = TPM2_ALG_CFB, .flags = tpm2_alg_util_flags_mode },
        { .name = "ecb", .id = TPM2_ALG_ECB, .flags = tpm2_alg_util_flags_mode },

        { .name = "symcipher", .id = TPM2_ALG_SYMCIPHER, .flags = tpm2_alg_util_flags_base },
        { .name = "keyedhash", .id = TPM2_ALG_KEYEDHASH, .flags = tpm2_alg_util_flags_base },

        // Misc
        { .name = "null", .id = TPM2_ALG_NULL, .flags = tpm2_alg_util_flags_misc | tpm2_alg_util_flags_rsa_scheme },
    };

    size_t i;
    for (i = 0; i < ARRAY_LEN(algs); i++) {
        const alg_pair *alg = &algs[i];
        alg_iter_res result = iterator(alg->id, alg->name, alg->flags,
                userdata);
        if (result != go) {
            return;
        }
    }
}

static alg_iter_res find_match(TPM2_ALG_ID id, const char *name,
        tpm2_alg_util_flags flags, void *userdata) {

    alg_pair *search_data = (alg_pair *) userdata;

    /*
     * if name, then search on name, else
     * search by id.
     */
    if (search_data->name && !strcmp(search_data->name, name)) {
        alg_iter_res res = search_data->flags & flags ? found : stop;
        if (res == found) {
            search_data->id = id;
            search_data->_flags = flags;
        }
        return res;
    } else if (search_data->id == id) {
        alg_iter_res res = search_data->flags & flags ? found : stop;
        if (res == found) {
            search_data->name = name;
            search_data->_flags = flags;
        }
        return res;
    }

    return go;
}

TPM2_ALG_ID tpm2_alg_util_strtoalg(const char *name, tpm2_alg_util_flags flags) {

    alg_pair userdata = { .name = name, .id = TPM2_ALG_ERROR, .flags = flags };

    if (name) {
        tpm2_alg_util_for_each_alg(find_match, &userdata);
    }

    return userdata.id;
}

const char *tpm2_alg_util_algtostr(TPM2_ALG_ID id, tpm2_alg_util_flags flags) {

    alg_pair userdata = { .name = NULL, .id = id, .flags = flags };

    tpm2_alg_util_for_each_alg(find_match, &userdata);

    return userdata.name;
}

tpm2_alg_util_flags tpm2_alg_util_algtoflags(TPM2_ALG_ID id) {

    alg_pair userdata = { .name = NULL, .id = id, .flags =
            tpm2_alg_util_flags_any, ._flags = tpm2_alg_util_flags_none };

    tpm2_alg_util_for_each_alg(find_match, &userdata);

    return userdata._flags;
}

UINT16 tpm2_alg_util_get_hash_size(TPMI_ALG_HASH id) {

    switch (id) {
    case TPM2_ALG_SHA1:
        return TPM2_SHA1_DIGEST_SIZE;
    case TPM2_ALG_SHA256:
        return TPM2_SHA256_DIGEST_SIZE;
    case TPM2_ALG_SHA384:
        return TPM2_SHA384_DIGEST_SIZE;
    case TPM2_ALG_SHA512:
        return TPM2_SHA512_DIGEST_SIZE;
    case TPM2_ALG_SM3_256:
        return TPM2_SM3_256_DIGEST_SIZE;
        /* no default */
    }

    return 0;
}

const char *tpm2_alg_util_ecc_to_str(TPM2_ECC_CURVE curve_id) {

    switch (curve_id) {
    case TPM2_ECC_NIST_P192:
        return "NIST p192";
    case TPM2_ECC_NIST_P224:
        return "NIST p224";
    case TPM2_ECC_NIST_P256:
        return "NIST p256";
    case TPM2_ECC_NIST_P384:
        return "NIST p384";
    case TPM2_ECC_NIST_P521:
        return "NIST 521";
    case TPM2_ECC_BN_P256:
        return "BN P256";
    case TPM2_ECC_BN_P638:
        return "BN P638";
    case TPM2_ECC_SM2_P256:
        return "SM2 p256";
        /* no default */
    }
    return NULL;
}

bool tpm2_alg_util_is_aes_size_valid(UINT16 size_in_bytes) {

    switch (size_in_bytes) {
    case 16:
    case 24:
    case 32:
        return true;
    default:
        LOG_ERR("Invalid AES key size, got %u bytes, expected 16,24 or 32",
                size_in_bytes);
        return false;
    }
}
