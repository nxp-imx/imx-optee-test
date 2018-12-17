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

static TEE_OperationHandle cipherEnc_op;
static TEE_OperationHandle cipherDec_op;

static void TA_FreeOp(uint8_t which)
{
	if ((which & ENCRYPT_ALGO) && (cipherEnc_op)) {
		TEE_FreeOperation(cipherEnc_op);
		cipherEnc_op = NULL;
	}
	if ((which & DECRYPT_ALGO) && (cipherDec_op)) {
		TEE_FreeOperation(cipherDec_op);
		cipherDec_op = NULL;
	}
}

TEE_Result TA_CipherPrepareAlgo(uint32_t algo, TEE_Param params[4])
{
	/* Cipher Preparation: Don't need to check again input params */
	TEE_Result       res;
	TEE_ObjectHandle hKey  = NULL;
	TEE_ObjectHandle hKey2 = NULL;
	TEE_ObjectType	 objType;

	uint32_t keysize;
	uint32_t op_keysize;
	uint8_t  *iv_key     = NULL;
	size_t   iv_key_size = 0;

	static uint8_t iv[16] = {0};

	keysize = params[1].value.a;

	/*
	 * Just in case there was an issue and Operation Handles
	 * was no freed
	 */
	TA_FreeOp(ENCRYPT_ALGO | DECRYPT_ALGO);

	/* Check the key size */
	objType = TEE_ALG_GET_KEY_TYPE(algo, false);
	switch (objType) {
	case TEE_TYPE_AES:
		if ((keysize != 128) && (keysize != 192) && (keysize != 256))
			return TEE_ERROR_BAD_PARAMETERS;
		break;

	case TEE_TYPE_DES:
		if (keysize != 64)
			return TEE_ERROR_BAD_PARAMETERS;
		/* Don't count the parity key size */
		keysize -= (keysize / 8);
		break;

	case TEE_TYPE_DES3:
		if ((keysize != 128) && (keysize != 192))
			return TEE_ERROR_BAD_PARAMETERS;
		/* Don't count the parity key size */
		keysize -= (keysize / 8);
		break;


	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	op_keysize = keysize;
	switch (TEE_ALG_GET_CHAIN_MODE(algo)) {
	case TEE_CHAIN_MODE_ECB_NOPAD:
		break;

	case TEE_CHAIN_MODE_CBC_NOPAD:
	case TEE_CHAIN_MODE_CTR:
	case TEE_CHAIN_MODE_CTS:
		iv_key      = iv;

		if ((objType == TEE_TYPE_DES) || (objType == TEE_TYPE_DES3))
			iv_key_size = 8;
		else
			iv_key_size = sizeof(iv);
		break;

	case TEE_CHAIN_MODE_XTS:
		iv_key      = iv;
		iv_key_size = sizeof(iv);
		op_keysize *= 2;
		break;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Prepare Keys and Operation handles */
	res = TEE_AllocateOperation(&cipherEnc_op, algo,
		TEE_MODE_ENCRYPT, op_keysize);
	CHECK(res, "TEE_AllocateOperation Encrypt Cipher",
		goto PrepareExit_Error;);

	res = TEE_AllocateOperation(&cipherDec_op, algo,
		TEE_MODE_DECRYPT, op_keysize);
	CHECK(res, "TEE_AllocateOperation Encrypt Cipher",
		goto PrepareExit_Error;);

	res = TEE_AllocateTransientObject(objType, keysize, &hKey);
	CHECK(res, "TEE_AllocateTransientObject Cipher",
		goto PrepareExit_Error;);

	res = TEE_GenerateKey(hKey, keysize, NULL, 0);
	CHECK(res, "TEE_GenerateKey Cipher", goto PrepareExit_Error;);

	if (algo == TEE_ALG_AES_XTS) {
		/* Allocate the second key */
		res = TEE_AllocateTransientObject(objType, keysize, &hKey2);
		CHECK(res, "TEE_AllocateTransientObject Cipher",
			goto PrepareExit_Error;);

		res = TEE_GenerateKey(hKey2, keysize, NULL, 0);
		CHECK(res, "TEE_GenerateKey Cipher", goto PrepareExit_Error;);

		res = TEE_SetOperationKey2(cipherEnc_op, hKey, hKey2);
		CHECK(res, "TEE_SetOperationKey2 Encrypt Cipher",
			goto PrepareExit_Error;);

		res = TEE_SetOperationKey2(cipherDec_op, hKey, hKey2);
		CHECK(res, "TEE_SetOperationKey2 Decrypt Cipher",
			goto PrepareExit_Error;);

		TEE_FreeTransientObject(hKey2);
	} else {
		res = TEE_SetOperationKey(cipherEnc_op, hKey);
		CHECK(res, "TEE_SetOperationKey Encrypt Cipher",
			goto PrepareExit_Error;);

		res = TEE_SetOperationKey(cipherDec_op, hKey);
		CHECK(res, "TEE_SetOperationKey Decrypt Cipher",
			goto PrepareExit_Error;);
	}

	TEE_FreeTransientObject(hKey);

	if (iv_key) {
		/* Generate IV Key */
		TEE_GenerateRandom(iv_key, iv_key_size);
	}

	TEE_CipherInit(cipherEnc_op, iv_key, iv_key_size);
	TEE_CipherInit(cipherDec_op, iv_key, iv_key_size);

	/*
	 * Set params[2].value.b = 1 to inform that decryption is supported.
	 */
	params[2].value.b = 1;

	return TEE_SUCCESS;

PrepareExit_Error:
	if (hKey)
		TEE_FreeTransientObject(hKey);
	if (hKey2)
		TEE_FreeTransientObject(hKey2);

	TA_FreeOp(ENCRYPT_ALGO | DECRYPT_ALGO);

	return res;
}

TEE_Result TA_CipherProcessAlgo(uint32_t algo __unused, TEE_Param params[4])
{
	/* Cipher Process: Don't need to check again input params */
	TEE_Result res;
	void *in, *out;
	uint32_t inSize;
	uint32_t outSize;

	in      = params[0].memref.buffer;
	inSize  = params[0].memref.size;
	out     = params[1].memref.buffer;
	outSize = params[1].memref.size;

	if (params[2].value.b == 0) {
		res = TEE_CipherUpdate(cipherEnc_op, in, inSize, out, &outSize);
		CHECK(res, "TEE_CipherUpdate Encrypt Cipher", return res;);
	} else {
		res = TEE_CipherUpdate(cipherDec_op, in, inSize, out, &outSize);
		CHECK(res, "TEE_CipherUpdate Decrypt Cipher", return res;);
	}
	return TEE_SUCCESS;

}

TEE_Result TA_CipherFreeAlgo(uint32_t algo, TEE_Param params[4])
{
	/* Cipher Free: Don't need to check again input params */
	TEE_Result res;
	void *in, *out;
	uint32_t inSize;
	uint32_t outSize;

	in      = params[0].memref.buffer;
	inSize  = 0;
	out     = params[1].memref.buffer;
	outSize = params[1].memref.size;

	if (TEE_ALG_GET_CHAIN_MODE(algo) == TEE_CHAIN_MODE_CTS)
		inSize = TEE_AES_BLOCK_SIZE;

	if (params[2].value.b == 0) {
		res = TEE_CipherDoFinal(cipherEnc_op, in,
			inSize, out, &outSize);
		CHECK(res, "TEE_CipherDoFinal Encrypt Cipher", return res;);

		TA_FreeOp(ENCRYPT_ALGO);
	} else {
		res = TEE_CipherDoFinal(cipherDec_op, in,
			inSize, out, &outSize);
		CHECK(res, "TEE_CipherDoFinal Decrypt Cipher", return res;);

		TA_FreeOp(DECRYPT_ALGO);
	}

	return TEE_SUCCESS;
}

