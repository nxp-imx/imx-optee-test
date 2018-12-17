// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018 NXP
 */

#include <stdio.h>
#include <trace.h>

#include <tee_ta_api.h>
#include <user_ta_header_defines.h>
#include <ta_crypto_perf.h>

#define ENCRYPT_ALGO (1 << 0)
#define DECRYPT_ALGO (1 << 1)

static TEE_OperationHandle asymcipherEnc_op;
static TEE_OperationHandle asymcipherDec_op;

static void TA_FreeOp(uint8_t which)
{
	if ((which & ENCRYPT_ALGO) && (asymcipherEnc_op)) {
		TEE_FreeOperation(asymcipherEnc_op);
		asymcipherEnc_op = NULL;
	}
	if ((which & DECRYPT_ALGO) && (asymcipherDec_op)) {
		TEE_FreeOperation(asymcipherDec_op);
		asymcipherDec_op = NULL;
	}
}

TEE_Result TA_AsymCipherPrepareAlgo(uint32_t algo, TEE_Param params[4])
{
	/*
	 * Asymmetric Cipher Preparation:
	 * Don't need to check again input params
	 */
	TEE_Result       res;
	TEE_ObjectHandle hKey  = NULL;
	TEE_ObjectType	 objType;

	uint32_t keysize;
	uint32_t op_keysize;

	keysize = params[1].value.a;

	/*
	 * Just in case there was an issue and Operation Handles
	 * was no freed
	 */
	TA_FreeOp(ENCRYPT_ALGO | DECRYPT_ALGO);

	/* Check the key size */
	objType = TEE_ALG_GET_KEY_TYPE(algo, true);
	switch (objType) {
	case TEE_TYPE_RSA_KEYPAIR:
		if ((keysize != 256) && (keysize != 512) &&
		    (keysize != 768) && (keysize != 1024) &&
			(keysize != 1536) && (keysize != 2048))
			return TEE_ERROR_BAD_PARAMETERS;
		break;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	op_keysize = keysize;

	/* Prepare Keys and Operation handles */
	res = TEE_AllocateOperation(&asymcipherEnc_op, algo,
		TEE_MODE_ENCRYPT, op_keysize);
	CHECK(res, "TEE_AllocateOperation Encrypt AsymCipher",
		goto PrepareExit_Error;);

	res = TEE_AllocateOperation(&asymcipherDec_op, algo,
		TEE_MODE_DECRYPT, op_keysize);
	CHECK(res, "TEE_AllocateOperation Decrypt AsymCipher",
		goto PrepareExit_Error;);

	res = TEE_AllocateTransientObject(objType, keysize, &hKey);
	CHECK(res, "TEE_AllocateTransientObject AsymCipher",
		goto PrepareExit_Error;);

	res = TEE_GenerateKey(hKey, keysize, NULL, 0);
	CHECK(res, "TEE_GenerateKey AsymCipher", goto PrepareExit_Error;);

	res = TEE_SetOperationKey(asymcipherEnc_op, hKey);
	CHECK(res, "TEE_SetOperationKey Encrypt AsymCipher",
		goto PrepareExit_Error;);

	res = TEE_SetOperationKey(asymcipherDec_op, hKey);
	CHECK(res, "TEE_SetOperationKey Decrypt AsymCipher",
		goto PrepareExit_Error;);

	TEE_FreeTransientObject(hKey);

	/*
	 * Set params[2].value.b = 1 to inform that decryption is supported.
	 */
	params[2].value.b = 1;

	return TEE_SUCCESS;

PrepareExit_Error:
	if (hKey)
		TEE_FreeTransientObject(hKey);

	TA_FreeOp(ENCRYPT_ALGO | DECRYPT_ALGO);

	return res;
}

TEE_Result TA_AsymCipherProcessAlgo(uint32_t algo __unused, TEE_Param params[4])
{
	/* Asymmetric Cipher Process: Don't need to check again input params */
	TEE_Result res;
	void *in, *out;
	uint32_t inSize;
	uint32_t outSize;

	in      = params[0].memref.buffer;
	inSize  = params[0].memref.size;
	out     = params[1].memref.buffer;
	outSize = params[1].memref.size;

	if (params[2].value.b == 0) {
		res = TEE_AsymmetricEncrypt(asymcipherEnc_op, NULL, 0,
			in, inSize, out, &outSize);
		CHECK(res, "TEE_AsymmetricEncrypt AsymCipher", return res;);
	} else {
		res = TEE_AsymmetricDecrypt(asymcipherDec_op, NULL, 0,
			in, inSize, out, &outSize);
		CHECK(res, "TEE_AsymmetricDecrypt AsymCipher", return res;);
	}

	return TEE_SUCCESS;

}

TEE_Result TA_AsymCipherFreeAlgo(uint32_t algo __unused, TEE_Param params[4])
{
	/* Asymmetric Cipher Free: Don't need to check again input params */
	if (params[2].value.b == 0)
		TA_FreeOp(ENCRYPT_ALGO);
	else
		TA_FreeOp(DECRYPT_ALGO);

	return TEE_SUCCESS;
}

