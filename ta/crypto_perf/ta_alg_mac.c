// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018 NXP
 */

#include <stdio.h>
#include <trace.h>

#include <tee_ta_api.h>
#include <user_ta_header_defines.h>
#include <ta_crypto_perf.h>

static TEE_OperationHandle mac_op;

static void TA_FreeOp(void)
{
	if (mac_op) {
		TEE_FreeOperation(mac_op);
		mac_op = NULL;
	}
}


TEE_Result TA_MacPrepareAlgo(uint32_t algo, TEE_Param params[4])
{
	/* Mac Preparation: Don't need to check again input params */
	TEE_Result       res;
	TEE_ObjectHandle hKey  = NULL;
	TEE_ObjectType   objType;

	uint32_t keysize;
	uint32_t op_keysize;
	uint8_t  *iv_key     = NULL;
	size_t   iv_key_size = 0;

	static uint8_t iv[16] = {0};

	keysize = params[1].value.a;

	/*
	 * Just in case there was an issue and Operation Handle
	 * was no freed
	 */
	TA_FreeOp();

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

	case TEE_TYPE_HMAC_MD5:
		if ((keysize < 64) || (keysize > 512))
			return TEE_ERROR_BAD_PARAMETERS;

		if (keysize % 8)
			return TEE_ERROR_BAD_PARAMETERS;
		break;

	case TEE_TYPE_HMAC_SHA1:
		if ((keysize < 80) || (keysize > 512))
			return TEE_ERROR_BAD_PARAMETERS;

		if (keysize % 8)
			return TEE_ERROR_BAD_PARAMETERS;
		break;

	case TEE_TYPE_HMAC_SHA224:
		if ((keysize < 112) || (keysize > 512))
			return TEE_ERROR_BAD_PARAMETERS;

		if (keysize % 8)
			return TEE_ERROR_BAD_PARAMETERS;
		break;

	case TEE_TYPE_HMAC_SHA256:
		if ((keysize < 192) || (keysize > 1024))
			return TEE_ERROR_BAD_PARAMETERS;

		if (keysize % 8)
			return TEE_ERROR_BAD_PARAMETERS;
		break;

	case TEE_TYPE_HMAC_SHA384:
		if ((keysize < 256) || (keysize > 1024))
			return TEE_ERROR_BAD_PARAMETERS;

		if (keysize % 8)
			return TEE_ERROR_BAD_PARAMETERS;
		break;

	case TEE_TYPE_HMAC_SHA512:
		if ((keysize < 256) || (keysize > 1024))
			return TEE_ERROR_BAD_PARAMETERS;

		if (keysize % 8)
			return TEE_ERROR_BAD_PARAMETERS;
		break;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	op_keysize = keysize;
	switch (TEE_ALG_GET_CHAIN_MODE(algo)) {
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
		break;
	}

	/* Prepare Keys */
	res = TEE_AllocateOperation(&mac_op, algo, TEE_MODE_MAC, op_keysize);
	CHECK(res, "TEE_AllocateOperation Mac", goto PrepareExit_Error;);

	res = TEE_AllocateTransientObject(objType, keysize, &hKey);
	CHECK(res, "TEE_AllocateTransientObject Mac", goto PrepareExit_Error;);

	res = TEE_GenerateKey(hKey, keysize, NULL, 0);
	CHECK(res, "TEE_GenerateKey Cipher", goto PrepareExit_Error;);

	res = TEE_SetOperationKey(mac_op, hKey);
	CHECK(res, "TEE_SetOperationKey Mac", goto PrepareExit_Error;);

	TEE_FreeTransientObject(hKey);

	if (iv_key) {
		/* Generate IV Key */
		TEE_GenerateRandom(iv_key, iv_key_size);
	}

	TEE_MACInit(mac_op, iv_key, iv_key_size);

	return TEE_SUCCESS;

PrepareExit_Error:
	TA_FreeOp();
	return res;
}

TEE_Result TA_MacProcessAlgo(uint32_t algo __unused, TEE_Param params[4])
{
	/* Mac Process: Don't need to check again input params */
	void *in;
	uint32_t inSize;

	in      = params[0].memref.buffer;
	inSize  = params[0].memref.size;

	TEE_MACUpdate(mac_op, in, inSize);

	return TEE_SUCCESS;

}

TEE_Result TA_MacFreeAlgo(uint32_t algo __unused, TEE_Param params[4])
{
	/* Mac Free: Don't need to check again input params */
	TEE_Result res;
	void *in, *out;
	uint32_t inSize;
	uint32_t outSize;

	in      = params[0].memref.buffer;
	/*
	 * Just to do the finalize without error
	 * Size must be blocksize at least
	 */
	inSize  = 16;
	out     = params[1].memref.buffer;
	outSize = params[1].memref.size;

	res = TEE_MACComputeFinal(mac_op, in, inSize, out, &outSize);
	CHECK(res, "TEE_MACComputeFinal Mac", return res;);

	TA_FreeOp();
	return TEE_SUCCESS;
}
