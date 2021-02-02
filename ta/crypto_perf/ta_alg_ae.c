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

static TEE_OperationHandle authenEnc_op;
static TEE_OperationHandle authenDec_op;

static uint8_t tag[64];
static size_t  tag_len;
static uint32_t gen_tag_len;
static uint8_t nonce[15];
static size_t  nonce_len;
static uint8_t aad[16];
static size_t  aad_len;

static void TA_FreeOp(uint8_t which)
{
	if ((which & ENCRYPT_ALGO) && (authenEnc_op)) {
		TEE_FreeOperation(authenEnc_op);
		authenEnc_op = NULL;
	}
	if ((which & DECRYPT_ALGO) && (authenDec_op)) {
		TEE_FreeOperation(authenDec_op);
		authenDec_op = NULL;
	}
}

TEE_Result TA_AuthenEncPrepareAlgo(uint32_t algo, TEE_Param params[4])
{
	/* Cipher Preparation: Don't need to check again input params */
	TEE_Result       res;
	TEE_ObjectHandle hKey  = NULL;
	TEE_ObjectType	 objType;

	uint8_t L;

	size_t  payload_len = 0;
	uint32_t keysize;
	uint32_t op_keysize;

	keysize = params[1].value.a;
	payload_len = params[1].value.b;

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

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	op_keysize = keysize;

	/* Calculate the value of L */
	for (L = 2; L < 9; L++) {
		if (payload_len < (size_t)(1 << (L * 3)))
			break;
	}

	if (L > 8)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (TEE_ALG_GET_CHAIN_MODE(algo)) {
	case TEE_CHAIN_MODE_CCM:
		/* Nonce Size is 15-L where 1 < L < 9 */
		nonce_len = (15 - L);
		TEE_GenerateRandom(nonce, nonce_len);
		tag_len = 32;
		gen_tag_len = 32;
		aad_len = 2;
		TEE_GenerateRandom(aad, aad_len);
		break;

	case TEE_CHAIN_MODE_GCM:
		/* Nonce Size is 15-L where 1 < L < 9 */
		nonce_len = (15 - L);
		TEE_GenerateRandom(nonce, nonce_len);
		tag_len = 96;
		gen_tag_len = 96;
		aad_len = 0;
		break;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Prepare Keys and Operation handles */
	res = TEE_AllocateOperation(&authenEnc_op, algo,
		TEE_MODE_ENCRYPT, op_keysize);
	CHECK(res, "TEE_AllocateOperation Encrypt Authentication",
		goto PrepareExit_Error;);

	res = TEE_AllocateOperation(&authenDec_op, algo,
		TEE_MODE_DECRYPT, op_keysize);
	CHECK(res, "TEE_AllocateOperation Decrypt Authentication",
		goto PrepareExit_Error;);

	res = TEE_AllocateTransientObject(objType, keysize, &hKey);
	CHECK(res, "TEE_AllocateTransientObject Authentication",
		goto PrepareExit_Error;);

	res = TEE_GenerateKey(hKey, keysize, NULL, 0);
	CHECK(res, "TEE_GenerateKey Authentication", goto PrepareExit_Error;);

	res = TEE_SetOperationKey(authenEnc_op, hKey);
	CHECK(res, "TEE_SetOperationKey Encrypt Authentication",
		goto PrepareExit_Error;);

	res = TEE_SetOperationKey(authenDec_op, hKey);
	CHECK(res, "TEE_SetOperationKey Decrypt Authentication",
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

TEE_Result TA_AuthenEncProcessAlgo(uint32_t algo __unused, TEE_Param params[4])
{
	/* Cipher Process: Don't need to check again input params */
	TEE_Result res;
	uint8_t *in, *out;
	uint32_t inSize;
	uint32_t outSize;
	uint32_t nb_loop;
	size_t   payload_len;

	in          = params[0].memref.buffer;
	payload_len = params[0].memref.size;
	out         = params[1].memref.buffer;

	/* Block size are 128 bits - 64 bytes */
	nb_loop = payload_len / 64;

	if (nb_loop == 0) {
		inSize  = payload_len;
		outSize = payload_len;
		nb_loop = 1;
	} else {
		inSize  = 64;
		outSize = 64;
	}

	if (params[2].value.b == 0) {
		res = TEE_AEInit(authenEnc_op, nonce, nonce_len,
			tag_len, aad_len, payload_len);
		CHECK(res, "TEE_AEInit Encrypt Authentication", return res;);

		if (aad_len)
			TEE_AEUpdateAAD(authenEnc_op, aad, aad_len);
	} else {
		res = TEE_AEInit(authenDec_op, nonce, nonce_len,
			tag_len, aad_len, payload_len);
		CHECK(res, "TEE_AEInit Decrypt Authentication", return res;);

		if (aad_len)
			TEE_AEUpdateAAD(authenDec_op, aad, aad_len);
	}

	for (nb_loop -= 1; nb_loop > 0; nb_loop--) {
		if (params[2].value.b == 0) {
			res = TEE_AEUpdate(authenEnc_op, in, inSize,
				out, &outSize);
			CHECK(res, "TEE_AEUpdate Encrypt", return res;);
		} else {
			res = TEE_AEUpdate(authenDec_op, in, inSize,
				out, &outSize);
			CHECK(res, "TEE_AEUpdate Decrypt", return res;);
		}
		in  += 64;
		out += 64;
	}

	if (params[2].value.b == 0) {
		res = TEE_AEEncryptFinal(authenEnc_op, in, inSize,
			out, &outSize, tag, &gen_tag_len);
		CHECK(res, "TEE_EAEncryptFinal Encrypt", return res;);
	} else {
		res = TEE_AEDecryptFinal(authenDec_op, in, inSize,
			out, &outSize, tag, gen_tag_len);
		CHECK(res, "TEE_EADecryptFinal Decrypt", return res;);
	}

	return TEE_SUCCESS;

}

TEE_Result TA_AuthenEncFreeAlgo(uint32_t algo __unused, TEE_Param params[4])
{
	if (params[2].value.b == 0)
		TA_FreeOp(ENCRYPT_ALGO);
	else
		TA_FreeOp(DECRYPT_ALGO);

	return TEE_SUCCESS;
}

