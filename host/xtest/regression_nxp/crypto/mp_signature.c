// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
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
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/opensslv.h>
#include <tee_client_api.h>
#include <tee_client_api_extensions.h>
#include <ta_manufacturing_protection.h>
#include <pta_imx_manufacturing_protection.h>
#include <utee_defines.h>

#define DEFAULT_INPUTS_FILENAME	   "inputs.txt"
#define DEFAULT_MPPUBKEY_FILENAME  "key.pem"
#define DEFAULT_SIGNATURE_FILENAME "sig.bin"

static int copy_buf_to_file(const void *buf, const char *filename, size_t size)
{
	FILE *f = NULL;

	/*
	 * opens the file in writing binary mode
	 * it's expected that we obtain a text filename
	 */
	f = fopen(filename, "wb");
	if (!f) {
		Do_ADBG_Log("%s: %s failed [%s]", __func__, "fopen", filename);
		return EXIT_FAILURE;
	}

	/* writes the buffer content into the file */
	if (fwrite(buf, 1, size, f) != size) {
		Do_ADBG_Log("%s: %s failed [%s]", __func__, "fwrite", filename);
		fclose(f);
		return EXIT_FAILURE;
	}

	fclose(f);
	return EXIT_SUCCESS;
}

/*
 * Retrieve the MP public key
 */
static int get_pubkey(ADBG_Case_t *const c, TEEC_Session *sess, uint8_t *pubkey,
		      size_t *pubkey_size, uint8_t *pubkey_pem,
		      size_t *pubkey_pem_size)
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

	if (!ADBG_EXPECT(c, TEEC_SUCCESS, res)) {
		Do_ADBG_Log("%s: PTA_IMX_MP_CMD_GET_PUBLIC_KEY res: %" PRIx32
			    ", origin: %" PRIx32,
			    __func__, res, err_origin);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/*
 * Call openssl tool dgst to verify the signature of a message
 */
static int verify_msg_sig(ADBG_Case_t *const c, uint8_t *mpmr_msg,
			  size_t mpmr_msg_size, const uint8_t *der_sig,
			  size_t der_sig_size, const uint8_t *pubkey_pem,
			  size_t pubkey_pem_size)
{
	char openssl_command[256] = {};

	/* Write the data to FS */
	if (copy_buf_to_file(mpmr_msg, DEFAULT_INPUTS_FILENAME,
			     mpmr_msg_size) != EXIT_SUCCESS) {
		Do_ADBG_Log("%s: %s failed [%s]", __func__, "copy_buf_to_file",
			    DEFAULT_INPUTS_FILENAME);
		return EXIT_FAILURE;
	}

	if (copy_buf_to_file(der_sig, DEFAULT_SIGNATURE_FILENAME,
			     der_sig_size) != EXIT_SUCCESS) {
		Do_ADBG_Log("%s: %s failed [%s]", __func__, "copy_buf_to_file",
			    DEFAULT_SIGNATURE_FILENAME);
		return EXIT_FAILURE;
	}

	if (copy_buf_to_file(pubkey_pem, DEFAULT_MPPUBKEY_FILENAME,
			     pubkey_pem_size) != EXIT_SUCCESS) {
		Do_ADBG_Log("%s: %s failed [%s]", __func__, "copy_buf_to_file",
			    DEFAULT_MPPUBKEY_FILENAME);
		return EXIT_FAILURE;
	}

	sprintf(openssl_command,
		"openssl dgst -sha256 -verify %s -signature %s %s",
		DEFAULT_MPPUBKEY_FILENAME, DEFAULT_SIGNATURE_FILENAME,
		DEFAULT_INPUTS_FILENAME);

	if (system(openssl_command) != 0) {
		Do_ADBG_Log("%s: %s failed [%s]", __func__, "system",
			    openssl_command);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/*
 * Convert a signature to a DER representation compatible with openssl dgst
 *
 * Openssl expect a signature of the DER format:
 * SEQUENCE {
 *    INTEGER 0x27361817047a4f09fd5ef43ab76eb1440ce8c12a0f31a8c02811282ea011b08d
 *    INTEGER 0x25d09c08895417fdd21523815e195a1bb4b780c398413702ee98978b9e6fffed
 * }
 * First INTEGER is the first half the signature binary buffer: R component
 * Second INTEGER is the second half the signature binary buffer: S component
 * Note: If the INTEGER has its MSB bit set, it needs to be appended a 0x00
 * Use OpenSSL to do it automatically
 */
static int convert_raw_sig_to_openssl_sig(ADBG_Case_t *const c,
					  const uint8_t *raw_sig,
					  size_t raw_sig_size, uint8_t *der_sig,
					  size_t *der_sig_size)
{
	int ret = EXIT_FAILURE;
	BIGNUM *bn_r = NULL;
	BIGNUM *bn_s = NULL;
	size_t half_size = raw_sig_size / 2;
	ECDSA_SIG *ec_sig = NULL;
	unsigned char *p = der_sig;
	size_t sig_req_size = 0;

	ec_sig = ECDSA_SIG_new();
	if (!ADBG_EXPECT_NOT_NULL(c, ec_sig)) {
		Do_ADBG_Log("%s: Failed to allocate EC signature", __func__);
		goto free_bn;
	}

#if OPENSSL_VERSION_NUMBER <= 0x10100006L
	BN_clear_free(ec_sig->r);
	BN_clear_free(ec_sig->s);
#endif

	bn_r = BN_bin2bn(raw_sig, half_size, NULL);
	if (!ADBG_EXPECT_NOT_NULL(c, bn_r)) {
		Do_ADBG_Log("%s: Failed to convert R", __func__);
		goto free_bn;
	}

	bn_s = BN_bin2bn(raw_sig + half_size, half_size, NULL);
	if (!ADBG_EXPECT_NOT_NULL(c, bn_s)) {
		Do_ADBG_Log("%s: Failed to convert S", __func__);
		goto free_bn;
	}

	/*
	 * When using ECDSA_SIG_set0, the memory management changes so after
	 * this call, the pointer on the BIGNUM shall not be free directly
	 */
#if OPENSSL_VERSION_NUMBER <= 0x10100006L
	ec_sig->r = bn_r;
	ec_sig->s = bn_s;
#else
	ret = ECDSA_SIG_set0(ec_sig, bn_r, bn_s);
	if (!ADBG_EXPECT(c, 1, ret)) {
		Do_ADBG_Log("%s: Failed to set R and S to signature", __func__);
		goto free_bn;
	}
#endif

	ret = i2d_ECDSA_SIG(ec_sig, NULL);
	if (ret == 0) {
		Do_ADBG_Log("%s: Failed to get size for signature", __func__);
		ret = EXIT_FAILURE;
		goto exit;
	}
	sig_req_size = ret;

	if (sig_req_size > *der_sig_size) {
		Do_ADBG_Log("%s: Buffer too small: %zu needed, %zu provided",
			    __func__, sig_req_size, *der_sig_size);
		*der_sig_size = sig_req_size;
		ret = EXIT_FAILURE;
		goto exit;
	}
	*der_sig_size = i2d_ECDSA_SIG(ec_sig, &p);

	ret = EXIT_SUCCESS;

	goto exit;

free_bn:
	if (bn_r)
		BN_free(bn_r);
	if (bn_s)
		BN_free(bn_s);

exit:
	if (ec_sig)
		ECDSA_SIG_free(ec_sig);

	return ret;
}

/*
 * Call MP API to sign a message using CAAM MP private key and verify it
 * When processing, CAAM is signing a concatenated message:
 *   [MPMR] + [USER MESSAGE]
 * When verifying it, the concatenated message must also be used
 */
static int sign_verify_message(ADBG_Case_t *const c, TEEC_Session *sess,
			       size_t msg_size, uint8_t *pubkey_pem,
			       size_t pubkey_pem_size)
{
	int ret = EXIT_FAILURE;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = {};
	uint32_t err_origin = 0;
	size_t raw_sig_size = MP_PUBKEY_SIZE_NAX;
	uint8_t *raw_sig = NULL;
	size_t der_sig_size = 256;
	uint8_t *der_sig = NULL;
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

	der_sig = malloc(der_sig_size);
	if (!ADBG_EXPECT_NOT_NULL(c, der_sig)) {
		Do_ADBG_Log("%s: %s failed: %" PRIx32,
			    "Allocation of signature DER", __func__, ret);
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

	ret = convert_raw_sig_to_openssl_sig(c, raw_sig, raw_sig_size, der_sig,
					     &der_sig_size);
	if (!ADBG_EXPECT(c, 0, ret)) {
		Do_ADBG_Log("%s: %s failed: %" PRIx32, __func__,
			    "convert_raw_sig_to_openssl_sig", ret);
		ret = EXIT_FAILURE;
		goto exit;
	}

	/* Verify signature with openssl */
	ret = verify_msg_sig(c, mpmr_msg, mpmr_msg_size, der_sig, der_sig_size,
			     pubkey_pem, pubkey_pem_size);
	if (!ADBG_EXPECT(c, EXIT_SUCCESS, ret)) {
		Do_ADBG_Log("%s: %s failed: %" PRIx32, __func__,
			    "verify_msg_sig", ret);
		ret = EXIT_FAILURE;
		goto exit;
	}

	ret = EXIT_SUCCESS;

exit:
	free(mpmr_msg);
	free(raw_sig);
	free(der_sig);

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

	ret = get_pubkey(c, &sess, pubkey, &pubkey_size, pubkey_pem,
			 &pubkey_pem_size);
	if (!ADBG_EXPECT(c, EXIT_SUCCESS, ret))
		goto exit;

	/* Loop over the different sizes of messages to sign */
	for (msg_size = msg_size_range_start; msg_size <= msg_size_range_end;
	     msg_size += msg_size_range_start) {
		Do_ADBG_BeginSubCase(c, "Sign message of size %zu", msg_size);

		ret = sign_verify_message(c, &sess, msg_size, pubkey_pem,
					  pubkey_pem_size);
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
