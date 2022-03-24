// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021-2022 NXP
 */

/*
 * Test of the signature of a message using the Manufacturing Protection key
 * This feature is only available on boards which are closed
 */

#include "xtest_helpers.h"
#include "xtest_test.h"
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include <tee_client_api_extensions.h>
#include <ta_manufacturing_protection.h>
#include <pta_manufact_protec.h>
#include <utee_defines.h>

#ifdef OPENSSL_FOUND
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#endif /* OPENSSL_FOUND */

/*
 * Retrieve the MP public key
 */
static TEEC_Result get_pubkey(ADBG_Case_t *const c, TEEC_Session *sess,
			      uint8_t *pubkey, size_t *pubkey_size,
			      uint8_t *pubkey_pem, size_t *pubkey_pem_size)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t err_origin = 0;

	/* Call PTA */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE);

	op.params[0].tmpref.buffer = (void *)pubkey;
	op.params[0].tmpref.size = *pubkey_size;

	op.params[1].tmpref.buffer = (void *)pubkey_pem;
	op.params[1].tmpref.size = *pubkey_pem_size;

	/* Execute a function in the TA by invoking it (call pta) */
	res = TEEC_InvokeCommand(sess, TA_MP_CMD_GET_MP_PUBK, &op, &err_origin);
	*pubkey_size = op.params[0].tmpref.size;
	*pubkey_pem_size = op.params[1].tmpref.size;

	if (res == TEEC_ERROR_NOT_SUPPORTED)
		return res;

	if (!ADBG_EXPECT(c, TEEC_SUCCESS, res)) {
		Do_ADBG_Log("%s: PTA_MP_CMD_GET_PUBLIC_KEY res: %" PRIx32
			    ", origin: %" PRIx32,
			    __func__, res, err_origin);
		return res;
	}

	return TEEC_SUCCESS;
}

#ifdef OPENSSL_FOUND
/*
 * Convert a signature to a DER representation following ASN1
 *
 * A signature of the DER format:
 * SEQUENCE {
 *    INTEGER 0x27361817047a4f09fd5ef43ab76eb1440ce8c12a0f31a8c02811282ea011b08d
 *    INTEGER 0x25d09c08895417fdd21523815e195a1bb4b780c398413702ee98978b9e6fffed
 * }
 * First INTEGER is the first half the signature binary buffer: R component
 * Second INTEGER is the second half the signature binary buffer: S component
 *
 * For simplicity, we are using the uncompressed form indicated by the first
 * byte
 *
 * Note: If the INTEGER has its MSB bit set, it needs to be appended a 0x00
 */
#define DER_UNCOMPRESSED_FORM 0x4

static int der_encap(uint8_t *der_sig, size_t *der_sig_size,
		     const uint8_t *raw_sig, size_t raw_sig_size)
{
	size_t req = 0;

	/*
	 * For the simple uncompressed form, we just need to add a leading
	 * byte
	 */
	req = raw_sig_size + 1;

	if (*der_sig_size < req) {
		*der_sig_size = req;
		return EXIT_FAILURE;
	}

	der_sig[0] = DER_UNCOMPRESSED_FORM;
	memcpy(der_sig + 1, raw_sig, raw_sig_size);

	*der_sig_size = req;

	return EXIT_SUCCESS;
}

static void print_ossl_errors(void)
{
	unsigned long error = 0;
	const char *file = NULL;
	int line = 0;
	const char *data = NULL;
	int flags = 0;

	while ((error = ERR_get_error_line_data(&file, &line, &data, &flags)))
		Do_ADBG_Log("OSSL(%lx)[%s@%d (%p | %x)]: %s", error, file, line,
			    data, flags, ERR_error_string(error, NULL));
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* From https://wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes */
static int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
	if (!r || !s)
		return 0;
	BN_clear_free(sig->r);
	BN_clear_free(sig->s);
	sig->r = r;
	sig->s = s;
	return 1;
}
#endif

static int verify_msg_sig_openssl(ADBG_Case_t *const c, uint8_t *mpmr_msg,
				  size_t mpmr_msg_size, const uint8_t *raw_sig,
				  size_t raw_sig_size, const uint8_t *pubkey,
				  size_t pubkey_size)
{
	int ret = EXIT_FAILURE;
	int err = 0;
	int success = 0;
	unsigned char digest[SHA256_DIGEST_LENGTH] = {};
	SHA256_CTX sha_ctx = {};
	ECDSA_SIG *sig = NULL;
	uint8_t *der_pubkey = NULL;
	size_t der_pubkey_size = 0;
	EC_KEY *key = NULL;
	EC_POINT *pub = NULL;
	EC_GROUP *group = NULL;
	BN_CTX *bn_ctx = NULL;
	size_t req = 0;
	size_t half_size = pubkey_size / 2;
	BIGNUM *bn_r = NULL;
	BIGNUM *bn_s = NULL;

	success = SHA256_Init(&sha_ctx);
	if (!ADBG_EXPECT(c, 1, success)) {
		Do_ADBG_Log("%s: %s failed", __func__, "SHA256_Init");
		goto exit;
	}

	success = SHA256_Update(&sha_ctx, mpmr_msg, mpmr_msg_size);
	if (!ADBG_EXPECT(c, 1, success)) {
		Do_ADBG_Log("%s: %s failed", __func__, "SHA256_Update");
		goto exit;
	}

	success = SHA256_Final(digest, &sha_ctx);
	if (!ADBG_EXPECT(c, 1, success)) {
		Do_ADBG_Log("%s: %s failed", __func__, "SHA256_Final");
		goto exit;
	}

	key = EC_KEY_new();
	if (!ADBG_EXPECT_NOT_NULL(c, key)) {
		Do_ADBG_Log("%s: %s failed", __func__, "EC_KEY_new");
		goto exit;
	}

	group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (!ADBG_EXPECT_NOT_NULL(c, group)) {
		Do_ADBG_Log("%s: %s failed", __func__,
			    "EC_GROUP_new_by_curve_name");
		goto exit;
	}

	success = EC_KEY_set_group(key, group);
	if (!ADBG_EXPECT(c, 1, success)) {
		Do_ADBG_Log("%s: %s failed", __func__, "EC_KEY_set_group");
		goto exit;
	}

	pub = EC_POINT_new(group);
	if (!ADBG_EXPECT_NOT_NULL(c, pub)) {
		Do_ADBG_Log("%s: %s failed", __func__, "EC_POINT_new");
		goto exit;
	}

	bn_ctx = BN_CTX_new();
	if (!ADBG_EXPECT_NOT_NULL(c, bn_ctx)) {
		Do_ADBG_Log("%s: %s failed", __func__, "BN_CTX_new");
		goto exit;
	}

	err = der_encap(NULL, &req, pubkey, pubkey_size);
	if (!ADBG_EXPECT(c, EXIT_FAILURE, err)) {
		Do_ADBG_Log("%s: %s failed", __func__, "der_encap get size");
		goto exit;
	}

	der_pubkey = malloc(req);
	if (!ADBG_EXPECT_NOT_NULL(c, der_pubkey)) {
		Do_ADBG_Log("%s: %s failed", __func__, "malloc");
		goto exit;
	}

	der_pubkey_size = req;

	/* We can pass the PEM version which already make it a der */
	err = der_encap(der_pubkey, &der_pubkey_size, pubkey, pubkey_size);
	if (!ADBG_EXPECT(c, EXIT_SUCCESS, err)) {
		Do_ADBG_Log("%s: %s failed", __func__, "der_encap pubkey");
		goto exit;
	}

	success = EC_POINT_oct2point(group, pub, der_pubkey, der_pubkey_size,
				     bn_ctx);
	if (!ADBG_EXPECT(c, 1, success)) {
		Do_ADBG_Log("%s: %s failed", __func__, "EC_POINT_oct2point");
		goto exit;
	}

	success = EC_KEY_set_public_key(key, pub);
	if (!ADBG_EXPECT(c, 1, success)) {
		Do_ADBG_Log("%s: %s failed", __func__, "EC_KEY_set_public_key");
		goto exit;
	}

	sig = ECDSA_SIG_new();
	if (!ADBG_EXPECT_NOT_NULL(c, sig)) {
		Do_ADBG_Log("%s: %s failed", __func__, "ECDSA_SIG_new");
		goto exit;
	}

	bn_r = BN_bin2bn(raw_sig, half_size, NULL);
	if (!ADBG_EXPECT_NOT_NULL(c, bn_r)) {
		Do_ADBG_Log("%s: %s failed", __func__, "BN_bin2bn");
		goto exit;
	}

	bn_s = BN_bin2bn(raw_sig + half_size, half_size, NULL);
	if (!ADBG_EXPECT_NOT_NULL(c, bn_s)) {
		Do_ADBG_Log("%s: %s failed", __func__, "BN_bin2bn");
		goto free_bn;
	}

	/*
	 * When using ECDSA_SIG_set0, the memory management changes so after
	 * this call, the pointer on the BIGNUM shall not be free directly
	 */
	success = ECDSA_SIG_set0(sig, bn_r, bn_s);
	if (!ADBG_EXPECT(c, 1, success)) {
		Do_ADBG_Log("%s: %s failed", __func__, "ECDSA_SIG_set0");
		goto free_bn;
	}

	success = ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, sig, key);
	if (!ADBG_EXPECT(c, 1, success)) {
		Do_ADBG_Log("%s: %s failed", __func__, "ECDSA_do_verify");
		goto exit;
	}

	ret = EXIT_SUCCESS;
	goto exit;

free_bn:
	free(bn_s);
	free(bn_r);

exit:
	print_ossl_errors();
	ECDSA_SIG_free(sig);
	EC_KEY_free(key);
	EC_POINT_free(pub);
	EC_GROUP_free(group);
	BN_CTX_free(bn_ctx);
	free(der_pubkey);

	return ret;
}
#else  /* OPENSSL_FOUND */
static int verify_msg_sig_openssl(ADBG_Case_t *const c, uint8_t *mpmr_msg,
				  size_t mpmr_msg_size, const uint8_t *raw_sig,
				  size_t raw_sig_size, const uint8_t *pubkey,
				  size_t pubkey_size)
{
	return EXIT_FAILURE;
}
#endif /* OPENSSL_FOUND */

/*
 * Call MP API to sign a message using CAAM MP private key and verify it
 * When processing, CAAM is signing a concatenated message:
 *   [MPMR] + [USER MESSAGE]
 * When verifying it, the concatenated message must also be used
 */
static int sign_verify_message(ADBG_Case_t *const c, TEEC_Session *sess,
			       size_t msg_size, uint8_t *pubkey,
			       size_t pubkey_size)
{
	int ret = EXIT_FAILURE;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = {};
	uint32_t err_origin = 0;
	size_t raw_sig_size = MP_PUBKEY_SIZE_NAX;
	uint8_t *raw_sig = NULL;
	/*
	 * The message to verify is the concatenation of the MPMR and the
	 * original message
	 */
	size_t mpmr_size = 32;
	uint8_t *mpmr = NULL;
	uint8_t *msg = NULL;
	size_t mpmr_msg_size = mpmr_size + msg_size;
	uint8_t *mpmr_msg = NULL;

	/* Allocate memory for other components */
	mpmr_msg = malloc(mpmr_msg_size);
	if (!ADBG_EXPECT_NOT_NULL(c, mpmr_msg))
		goto exit;

	mpmr = mpmr_msg;
	msg = mpmr_msg + mpmr_size;

	raw_sig = malloc(raw_sig_size);
	if (!ADBG_EXPECT_NOT_NULL(c, raw_sig)) {
		Do_ADBG_Log("%s: %s failed: %" PRIx32,
			    "Allocation of signature", __func__, ret);
		goto exit;
	}

	/* Create dummy message of the length required */
	memset(msg, 'A', msg_size);

	/* Call PTA */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	op.params[0].tmpref.buffer = (void *)msg;
	op.params[0].tmpref.size = msg_size;

	op.params[1].tmpref.buffer = (void *)raw_sig;
	op.params[1].tmpref.size = raw_sig_size;

	op.params[2].tmpref.buffer = (void *)mpmr;
	op.params[2].tmpref.size = mpmr_size;

	/* Execute a function in the TA by invoking it (call pta) */
	res = TEEC_InvokeCommand(sess, TA_MP_CMD_SIGN_DATA, &op, &err_origin);
	raw_sig_size = op.params[1].tmpref.size;
	mpmr_size = op.params[2].tmpref.size;

	if (!ADBG_EXPECT(c, TEEC_SUCCESS, res)) {
		Do_ADBG_Log("%s: TA_MP_CMD_SIGN_DATA res: %" PRIx32
			    ", origin: %" PRIx32,
			    __func__, res, err_origin);
		goto exit;
	}

	ret = verify_msg_sig_openssl(c, mpmr_msg, mpmr_msg_size, raw_sig,
				     raw_sig_size, pubkey, pubkey_size);
	if (!ADBG_EXPECT(c, EXIT_SUCCESS, ret)) {
		Do_ADBG_Log("%s: %s failed: %" PRIx32, __func__,
			    "verify_msg_sig_openssl", ret);
		goto exit;
	}

	ret = EXIT_SUCCESS;

exit:
	free(mpmr_msg);
	free(raw_sig);

	return ret;
}

static bool mp_pta_is_present(ADBG_Case_t *const c, TEEC_Context *ctx)
{
	static int present;
	TEEC_Session sess = {};
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_UUID uuid = PTA_MANUFACT_PROTEC_UUID;
	uint32_t err_origin = 0;

	if (present != 0)
		goto exit;

	res = TEEC_OpenSession(ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
			       &err_origin);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		present = -1;
		goto exit;
	}

	if (res == TEEC_SUCCESS)
		TEEC_CloseSession(&sess);

	present = 1;

exit:
	return (present >= 0) ? true : false;
}

static void nxp_crypto_0020(ADBG_Case_t *const c)
{
	int ret = EXIT_FAILURE;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	size_t msg_size_range_start = 256;
	size_t msg_size_range_end = 4096;
	size_t msg_size = 0;
	size_t pubkey_size = MP_PUBKEY_SIZE_NAX;
	uint8_t *pubkey = NULL;
	size_t pubkey_pem_size = MP_PUBKEY_PEM_SIZE_MAX;
	uint8_t *pubkey_pem = NULL;
	TEEC_Context ctx = {};
	TEEC_Session sess = {};
	TEEC_UUID uuid = TA_MANUFACTURING_PROTECTION_UUID;
	uint32_t err_origin = 0;

	/* Initialize a context connecting to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (!ADBG_EXPECT(c, TEEC_SUCCESS, res))
		goto exit;

	if (!mp_pta_is_present(c, &ctx)) {
		Do_ADBG_Log("Skip test, pseudo TA not found");
		return;
	}

#ifndef OPENSSL_FOUND
	Do_ADBG_Log("Skip test, openssl not found");
	return;
#endif /* OPENSSL_FOUND */

	pubkey = malloc(pubkey_size);
	if (!ADBG_EXPECT_NOT_NULL(c, pubkey))
		goto exit;

	pubkey_pem = malloc(pubkey_pem_size);
	if (!ADBG_EXPECT_NOT_NULL(c, pubkey_pem))
		goto exit;

	/* open a session with the TA */
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	if (!ADBG_EXPECT(c, TEEC_SUCCESS, res))
		goto exit;

	res = get_pubkey(c, &sess, pubkey, &pubkey_size, pubkey_pem,
			 &pubkey_pem_size);

	if (res == TEEC_ERROR_NOT_SUPPORTED) {
		Do_ADBG_Log("Skip test, MP not functional");
		return;
	}

	if (!ADBG_EXPECT(c, TEEC_SUCCESS, res))
		goto exit;

	/* Loop over the different sizes of messages to sign */
	for (msg_size = msg_size_range_start; msg_size <= msg_size_range_end;
	     msg_size += msg_size_range_start) {
		Do_ADBG_BeginSubCase(c, "Sign message of size %zu", msg_size);

		ret = sign_verify_message(c, &sess, msg_size, pubkey,
					  pubkey_size);
		if (!ADBG_EXPECT(c, EXIT_SUCCESS, ret)) {
			Do_ADBG_EndSubCase(c, NULL);
			goto exit;
		}

		Do_ADBG_EndSubCase(c, NULL);
	}

exit:
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	free(pubkey);
	free(pubkey_pem);
}

ADBG_CASE_DEFINE(regression_nxp, 0020, nxp_crypto_0020,
		 "Test MP signature of messages");

static void nxp_crypto_0021(ADBG_Case_t *const c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Context ctx = {};
	TEEC_Session sess = {};
	TEEC_UUID uuid = PTA_MANUFACT_PROTEC_UUID;
	uint32_t err_origin = 0;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (!ADBG_EXPECT(c, TEEC_SUCCESS, res))
		return;

	if (!mp_pta_is_present(c, &ctx)) {
		Do_ADBG_Log("Skip test, pseudo TA not found");
		return;
	}

	/* open a session with the PTA, should fail */
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);

	ADBG_EXPECT(c, TEEC_ERROR_ACCESS_DENIED, res);
	ADBG_EXPECT(c, TEEC_ORIGIN_TRUSTED_APP, err_origin);

	if (res == TEEC_SUCCESS)
		TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
}

ADBG_CASE_DEFINE(regression_nxp, 0021, nxp_crypto_0021,
		 "Test MP PTA cannot be opened from CA");
