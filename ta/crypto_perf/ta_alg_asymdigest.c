// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018 NXP
 */

#include <stdio.h>
#include <trace.h>
#include <string.h>

#include <tee_ta_api.h>
#include <user_ta_header_defines.h>
#include <ta_crypto_perf.h>

#define SIGN_ALGO	(1 << 0)
#define VERIFY_ALGO	(1 << 1)

static TEE_OperationHandle asymdigestSign_op;
static TEE_OperationHandle asymdigestVerif_op;
static uint8_t *prime;
static uint8_t *subprime;
static uint8_t *base;
static uint8_t *private;
static uint8_t *public_x;
static uint8_t *public_y;

static void TA_FreeOp(uint8_t which)
{
	if ((which & SIGN_ALGO) && (asymdigestSign_op)) {
		TEE_FreeOperation(asymdigestSign_op);
		asymdigestSign_op = NULL;
	}
	if ((which & VERIFY_ALGO) && (asymdigestVerif_op)) {
		TEE_FreeOperation(asymdigestVerif_op);
		asymdigestVerif_op = NULL;
	}

	if (base)
		TEE_Free(base);
	if (subprime)
		TEE_Free(subprime);
	if (prime)
		TEE_Free(prime);
	if (private)
		TEE_Free(private);
	if (public_x)
		TEE_Free(public_x);
	if (public_y)
		TEE_Free(public_y);

	base     = NULL;
	subprime = NULL;
	prime    = NULL;
	private  = NULL;
	public_x = NULL;
	public_y = NULL;
}

TEE_Result TA_AsymDigestPrepareAlgo(uint32_t algo, TEE_Param params[4])
{
	/*
	 * Asymmetric Digest Preparation:
	 * Don't need to check again input params
	 */
	TEE_Result       res;
	TEE_ObjectHandle hKey  = NULL;
	TEE_ObjectType	 objType;
	TEE_Attribute    attrs[5];
	uint8_t          nb_attrs = 0;
	uint32_t         q_size   = 0;

	uint32_t keysize;
	uint32_t op_keysize;

	keysize = params[1].value.a;

	/*
	 * Just in case there was an issue and Operation Handles
	 * was no freed
	 */
	TA_FreeOp(SIGN_ALGO | VERIFY_ALGO);

	/* Check the key size */
	objType = TEE_ALG_GET_KEY_TYPE(algo, true);

	op_keysize = keysize;

	switch (objType) {
	case TEE_TYPE_RSA_KEYPAIR:
		if ((keysize < 256) || (keysize > 4096))
			return TEE_ERROR_BAD_PARAMETERS;

		if (keysize % 64)
			return TEE_ERROR_BAD_PARAMETERS;

		break;

	case TEE_TYPE_DSA_KEYPAIR:
		if ((keysize < 512) || (keysize > 3072))
			return TEE_ERROR_BAD_PARAMETERS;

		if (keysize % 64)
			return TEE_ERROR_BAD_PARAMETERS;


		if (keysize <= 1024)
			q_size = 20;
		else if (keysize <= 2048)
			q_size = 32;
		else if (keysize <= 3072)
			q_size = 35;
		else
			q_size = 40;

		prime    = TEE_Malloc((keysize / 8), 0);
		subprime = TEE_Malloc(q_size, 0);
		base     = TEE_Malloc((keysize / 8), 0);

		if ((!prime) || (!subprime) || (!base)) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto PrepareExit_Error;
		}

		attrs[0].attributeID = TEE_ATTR_DSA_PRIME;
		attrs[0].content.ref.buffer = (void *)prime;
		attrs[0].content.ref.length = keysize / 8;

		attrs[1].attributeID = TEE_ATTR_DSA_SUBPRIME;
		attrs[1].content.ref.buffer = (void *)subprime;
		attrs[1].content.ref.length = q_size;

		attrs[2].attributeID = TEE_ATTR_DSA_BASE;
		attrs[2].content.ref.buffer = (void *)base;
		attrs[2].content.ref.length = keysize / 8;

		nb_attrs = 3;

		break;

	case TEE_TYPE_ECDSA_KEYPAIR:
		if ((keysize < 192) || (keysize > 521))
			return TEE_ERROR_BAD_PARAMETERS;

		attrs[3].attributeID = TEE_ATTR_ECC_CURVE;
		attrs[3].content.value.b = 0;

		switch (algo) {
		case TEE_ALG_ECDSA_P192:
			attrs[3].content.value.a = TEE_ECC_CURVE_NIST_P192;
			break;

		case TEE_ALG_ECDSA_P224:
			attrs[3].content.value.a =  TEE_ECC_CURVE_NIST_P224;
			break;

		case TEE_ALG_ECDSA_P256:
			attrs[3].content.value.a =  TEE_ECC_CURVE_NIST_P256;
			break;

		case TEE_ALG_ECDSA_P384:
			attrs[3].content.value.a = TEE_ECC_CURVE_NIST_P384;
			break;

		case TEE_ALG_ECDSA_P521:
			attrs[3].content.value.a = TEE_ECC_CURVE_NIST_P521;
			keysize = 528;
			break;

		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}

		private  = TEE_Malloc(keysize / 8, 0);
		public_x = TEE_Malloc(keysize / 8, 0);
		public_y = TEE_Malloc(keysize / 8, 0);

		if ((!private) || (!public_x) || (!public_y)) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto PrepareExit_Error;
		}

		attrs[0].attributeID = TEE_ATTR_ECC_PRIVATE_VALUE;
		attrs[0].content.ref.buffer = (void *)private;
		attrs[0].content.ref.length = keysize / 8;

		attrs[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
		attrs[1].content.ref.buffer = (void *)public_x;
		attrs[1].content.ref.length = keysize / 8;

		attrs[2].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
		attrs[2].content.ref.buffer = (void *)public_y;
		attrs[2].content.ref.length = keysize / 8;

		nb_attrs = 4;
		break;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Prepare Keys and Operation handles */
	res = TEE_AllocateOperation(&asymdigestSign_op, algo,
		TEE_MODE_SIGN, op_keysize);
	CHECK(res, "TEE_AllocateOperation Encrypt AsymDigest",
		goto PrepareExit_Error;);

	res = TEE_AllocateOperation(&asymdigestVerif_op, algo,
		TEE_MODE_VERIFY, op_keysize);
	CHECK(res, "TEE_AllocateOperation Decrypt AsymDigest",
		goto PrepareExit_Error;);

	res = TEE_AllocateTransientObject(objType, op_keysize, &hKey);
	CHECK(res, "TEE_AllocateTransientObject AsymDigest",
		goto PrepareExit_Error;);

	res = TEE_GenerateKey(hKey, op_keysize, attrs, nb_attrs);
	CHECK(res, "TEE_GenerateKey AsymDigest", goto PrepareExit_Error;);

	res = TEE_SetOperationKey(asymdigestSign_op, hKey);
	CHECK(res, "TEE_SetOperationKey Encrypt AsymDigest",
		goto PrepareExit_Error;);

	res = TEE_SetOperationKey(asymdigestVerif_op, hKey);
	CHECK(res, "TEE_SetOperationKey Decrypt AsymDigest",
		goto PrepareExit_Error;);

	TEE_FreeTransientObject(hKey);

	/*
	 * Set params[2].value.b = 1 to inform that verify is supported.
	 */
	params[2].value.b = 1;

	return TEE_SUCCESS;

PrepareExit_Error:
	if (hKey)
		TEE_FreeTransientObject(hKey);

	TA_FreeOp(SIGN_ALGO | VERIFY_ALGO);

	return res;
}

TEE_Result TA_AsymDigestProcessAlgo(uint32_t algo, TEE_Param params[4])
{
	/*
	 * Asymmetric Digest Process:
	 * Don't need to check again input params
	 */
	TEE_Result res;
	void *in, *out;
	uint32_t inSize;
	uint32_t outSize;
	TEE_Attribute attrs[1];
	uint8_t       nb_attrs = 0;

	in      = params[0].memref.buffer;
	inSize  = params[0].memref.size;
	out     = params[1].memref.buffer;
	outSize = params[1].memref.size;

	if (TEE_ALG_GET_CHAIN_MODE(algo) == TEE_CHAIN_MODE_PKCS1_PSS_MGF1) {
		attrs[0].attributeID = TEE_ATTR_RSA_PSS_SALT_LENGTH;
		attrs[0].content.value.a = 20;
		nb_attrs = 1;
	}

	if (params[2].value.b == 0) {
		res = TEE_AsymmetricSignDigest(asymdigestSign_op, attrs,
			nb_attrs, in, inSize, out, &outSize);
		/* Update the size of the output */
		params[1].memref.size = outSize;
		CHECK(res, "TEE_AsymmetricSignDigest AsymDigest",
			return res;);
	} else {
		res = TEE_AsymmetricVerifyDigest(asymdigestVerif_op, attrs,
			nb_attrs, in, inSize, out, outSize);
		CHECK(res, "TEE_AsymmetricVerifyDigest AsymDigest",
			return res;);
	}

	return TEE_SUCCESS;

}

TEE_Result TA_AsymDigestFreeAlgo(uint32_t algo __unused, TEE_Param params[4])
{
	/* Asymmetric Digest Free: Don't need to check again input params */
	if (params[2].value.b == 0)
		TA_FreeOp(SIGN_ALGO);
	else
		TA_FreeOp(VERIFY_ALGO);

	return TEE_SUCCESS;
}

