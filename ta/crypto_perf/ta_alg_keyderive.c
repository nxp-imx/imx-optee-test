// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018 NXP
 */

#include <stdio.h>
#include <trace.h>

#include <tee_ta_api.h>
#include <user_ta_header_defines.h>
#include <ta_crypto_perf.h>

static TEE_OperationHandle deriveKey_op;
static uint8_t *prime;
static uint8_t *base;
static uint8_t *public_key;
static uint8_t *public_key2;
static uint8_t *private_key;
static uint8_t *public_x;
static uint8_t *public_y;
static uint8_t *public_x_2;
static uint8_t *public_y_2;

static TEE_ObjectHandle hKeyDerived;

static void TA_FreeOp(void)
{
	if (deriveKey_op) {
		TEE_FreeOperation(deriveKey_op);
		deriveKey_op = NULL;
	}

	if (hKeyDerived) {
		TEE_FreeTransientObject(hKeyDerived);
		hKeyDerived = NULL;
	}

	if (prime)
		TEE_Free(prime);
	if (base)
		TEE_Free(base);
	if (public_key)
		TEE_Free(public_key);
	if (public_key2)
		TEE_Free(public_key2);
	if (private_key)
		TEE_Free(private_key);
	if (public_x)
		TEE_Free(public_x);
	if (public_y)
		TEE_Free(public_y);
	if (public_x_2)
		TEE_Free(public_x_2);
	if (public_y_2)
		TEE_Free(public_y_2);

	prime       = NULL;
	base        = NULL;
	public_key  = NULL;
	public_key2 = NULL;
	private_key = NULL;
	public_x    = NULL;
	public_y    = NULL;
	public_x_2  = NULL;
	public_y_2  = NULL;

}

TEE_Result TA_KeyDerivePrepareAlgo(uint32_t algo, TEE_Param params[4])
{
	/*
	 * Asymmetric Cipher Preparation:
	 * Don't need to check again input params
	 */
	TEE_Result       res;
	TEE_ObjectHandle hKey  = NULL;
	TEE_ObjectType	 objType;
	TEE_Attribute    attrs[5];
	uint8_t          nb_attrs = 0;

	uint32_t keysize;
	uint32_t op_keysize;

	keysize = params[1].value.a;

	/*
	 * Just in case there was an issue and Operation Handles
	 * was no freed
	 */
	TA_FreeOp();

	/* Check the key size */
	objType = TEE_ALG_GET_KEY_TYPE(algo, true);

	op_keysize = keysize;

	switch (objType) {
	case TEE_TYPE_DH_KEYPAIR:
		if ((keysize < 256) || (keysize > 2048))
			return TEE_ERROR_BAD_PARAMETERS;

		prime       = TEE_Malloc(keysize / 8, 0);
		base        = TEE_Malloc(keysize / 64, 0);
		public_key  = TEE_Malloc(keysize / 8, 0);
		public_key2 = TEE_Malloc(keysize / 8, 0);
		private_key = TEE_Malloc(keysize / 8, 0);

		if ((!prime) || (!base) || (!public_key) || (!private_key) ||
			(!public_key2)) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto PrepareExit_Error;
		}

		TEE_GenerateRandom(prime, keysize / 8);
		TEE_GenerateRandom(base, keysize / 64);
		TEE_GenerateRandom(public_key2, keysize / 8);

		/*
		 * WARNING if prime is even, PKHA Exponentiation
		 * generate an error ensure if it will be even
		 * all the time
		 */
		prime[(keysize / 8) - 1] |= 1;

		attrs[0].attributeID = TEE_ATTR_DH_PRIME;
		attrs[0].content.ref.buffer = (void *)prime;
		attrs[0].content.ref.length = keysize / 8;

		attrs[1].attributeID = TEE_ATTR_DH_BASE;
		attrs[1].content.ref.buffer = (void *)base;
		attrs[1].content.ref.length = keysize / 64;

		attrs[2].attributeID = TEE_ATTR_DH_PUBLIC_VALUE;
		attrs[2].content.ref.buffer = (void *)public_key;
		attrs[2].content.ref.length = keysize / 8;

		attrs[3].attributeID = TEE_ATTR_DH_PRIVATE_VALUE;
		attrs[3].content.ref.buffer = (void *)private_key;
		attrs[3].content.ref.length = keysize / 8;

		nb_attrs = 4;

		break;

	case TEE_TYPE_ECDH_KEYPAIR:
		if ((keysize < 192) || (keysize > 528))
			return TEE_ERROR_BAD_PARAMETERS;

		attrs[3].attributeID = TEE_ATTR_ECC_CURVE;
		attrs[3].content.value.b = 0;

		switch (algo) {
		case TEE_ALG_ECDH_P192:
			attrs[3].content.value.a = TEE_ECC_CURVE_NIST_P192;
			break;

		case TEE_ALG_ECDH_P224:
			attrs[3].content.value.a =  TEE_ECC_CURVE_NIST_P224;
			break;

		case TEE_ALG_ECDH_P256:
			attrs[3].content.value.a =  TEE_ECC_CURVE_NIST_P256;
			break;

		case TEE_ALG_ECDH_P384:
			attrs[3].content.value.a = TEE_ECC_CURVE_NIST_P384;
			break;

		case TEE_ALG_ECDH_P521:
			attrs[3].content.value.a = TEE_ECC_CURVE_NIST_P521;
			op_keysize = 521;
			break;

		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}

		private_key = TEE_Malloc(keysize / 8, 0);
		public_x    = TEE_Malloc(keysize / 8, 0);
		public_y    = TEE_Malloc(keysize / 8, 0);
		public_x_2  = TEE_Malloc(keysize / 8, 0);
		public_y_2  = TEE_Malloc(keysize / 8, 0);

		if ((!private_key) || (!public_x) || (!public_y)) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto PrepareExit_Error;
		}

		TEE_GenerateRandom(public_x_2, keysize / 8);
		TEE_GenerateRandom(public_y_2, keysize / 8);

		attrs[0].attributeID = TEE_ATTR_ECC_PRIVATE_VALUE;
		attrs[0].content.ref.buffer = (void *)private_key;
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
	res = TEE_AllocateOperation(&deriveKey_op, algo,
		TEE_MODE_DERIVE, op_keysize);
	CHECK(res, "TEE_AllocateOperation Key Derive",
		goto PrepareExit_Error;);

	res = TEE_AllocateTransientObject(objType, op_keysize, &hKey);
	CHECK(res, "TEE_AllocateTransientObject Key Derive",
		goto PrepareExit_Error;);

	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
		keysize, &hKeyDerived);
	CHECK(res, "TEE_AllocateTransientObject Key Derive",
		goto PrepareExit_Error;);

	res = TEE_GenerateKey(hKey, op_keysize, attrs, nb_attrs);
	CHECK(res, "TEE_GenerateKey Key Derive", goto PrepareExit_Error;);

	res = TEE_SetOperationKey(deriveKey_op, hKey);
	CHECK(res, "TEE_SetOperationKey Derive Key", goto PrepareExit_Error;);

	TEE_FreeTransientObject(hKey);

	/*
	 * Set params[2].value.b = 0 to inform that there is no reverse.
	 */
	params[2].value.b = 0;

	return TEE_SUCCESS;

PrepareExit_Error:
	if (hKey)
		TEE_FreeTransientObject(hKey);

	TA_FreeOp();
	return res;
}

TEE_Result TA_KeyDeriveProcessAlgo(uint32_t algo, TEE_Param params[4])
{
	TEE_Result    res;
	TEE_Attribute attrs[2];
	uint8_t       nb_attrs = 0;
	void *out;
	uint32_t inSize;
	uint32_t outSize;

	inSize  = params[0].memref.size;
	out     = params[1].memref.buffer;
	outSize = params[1].memref.size;

	if (algo == TEE_ALG_DH_DERIVE_SHARED_SECRET) {
		attrs[0].attributeID = TEE_ATTR_DH_PUBLIC_VALUE;
		attrs[0].content.ref.buffer = (void *)public_key2;
		attrs[0].content.ref.length = inSize;
		nb_attrs = 1;
	} else {
		attrs[0].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
		attrs[0].content.ref.buffer = (void *)public_x_2;
		attrs[0].content.ref.length = inSize;

		attrs[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
		attrs[1].content.ref.buffer = (void *)public_y_2;
		attrs[1].content.ref.length = inSize;
		nb_attrs = 2;

	}

	if (params[2].value.b == 0) {
		TEE_ResetTransientObject(hKeyDerived);

		TEE_DeriveKey(deriveKey_op, attrs, nb_attrs, hKeyDerived);

		res = TEE_GetObjectBufferAttribute(hKeyDerived,
			TEE_ATTR_SECRET_VALUE,
			out, &outSize);
		CHECK(res, "TEE_GetObjectBufferAttribute Key Derive",
			return res;);
	}

	return TEE_SUCCESS;

}

TEE_Result TA_KeyDeriveFreeAlgo(uint32_t algo __unused,
	TEE_Param params[4] __unused)
{
	TA_FreeOp();

	return TEE_SUCCESS;
}

