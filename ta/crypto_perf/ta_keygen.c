// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <string.h>

#include <ta_crypto_perf.h>
#include <test_vectors_dsa.h>

static TEE_ObjectHandle hkey_gen;
static TEE_Attribute key_gen_attrs[4];
static uint32_t key_gen_nb_attrs;

static uint8_t dh_prime[2048 / 8];
static uint8_t dh_base[2048 / 64];

TEE_Result TA_PrepareGen(uint32_t ParamTypes, TEE_Param Params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t keysize = 0;
	uint32_t alg_id = 0;
	TEE_ObjectType objType = 0;
	uint32_t exp_ParamTypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						  TEE_PARAM_TYPE_VALUE_INPUT,
						  TEE_PARAM_TYPE_VALUE_OUTPUT,
						  TEE_PARAM_TYPE_NONE);
	bool with_private = false;
	uint32_t alg_class = 0;
	uint32_t curve = 0;
	unsigned int n = 0;
	uint32_t prime_len = 0;
	uint32_t base_len = 0;

	if (ParamTypes != exp_ParamTypes) {
		EMSG("Parameter type differ: %" PRIx32 " instead of %" PRIx32,
		     ParamTypes, exp_ParamTypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!Params[0].memref.buffer) {
		EMSG("Name of the algorithm not provided");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	keysize = Params[1].value.a;

	/* Retrieve the algorithm identifier from the name */
	alg_id = get_alg_id(Params[0].memref.buffer, Params[0].memref.size);
	if (alg_id == (uint32_t)(-1)) {
		EMSG("Cannot retrieve algorithm ID from name");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	Params[2].value.a = alg_id;
	Params[2].value.b = 0;

	/* We need the private key as the public one cannot be generated */
	alg_class = TEE_ALG_GET_CLASS(alg_id);

	if (alg_class == TEE_OPERATION_DIGEST) {
		EMSG("Digest is not supported for key generation");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (alg_class == TEE_OPERATION_ASYMMETRIC_CIPHER ||
	    alg_class == TEE_OPERATION_ASYMMETRIC_SIGNATURE ||
	    alg_class == TEE_OPERATION_KEY_DERIVATION)
		with_private = true;

	objType = TEE_ALG_GET_KEY_TYPE(alg_id, with_private);

	DMSG("alg: %" PRIx32 " obj: %" PRIx32 " size: %" PRIx32, alg_id,
	     objType, keysize);

	/* Clean in case previous call corrupted it */
	TA_FreeGen();

	/* Set additional parameters if required */
	switch (objType) {
	case TEE_TYPE_RSA_KEYPAIR:
		if (keysize < 256 || keysize > 4096) {
			EMSG("RSA key pair size %" PRIx32 " out of bound",
			     keysize);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		if (keysize % 64) {
			EMSG("RSA key pair %" PRIx32 " quanta not respected",
			     keysize);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		break;

	case TEE_TYPE_DSA_KEYPAIR:
		if (keysize < 512 || keysize > 3072) {
			EMSG("RSA key pair size %" PRIx32 " out of bound",
			     keysize);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		if (keysize % 64) {
			EMSG("RSA key pair %" PRIx32 " quanta not respected",
			     keysize);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		/* Use existing data to generate the key */
		for (n = 0; n < ARRAY_SIZE(dsa_key_types); n++) {
			if (dsa_key_types[n].key_size_bits != keysize)
				continue;

			key_gen_attrs[0].attributeID = TEE_ATTR_DSA_PRIME;
			key_gen_attrs[0].content.ref.buffer =
				(void *)dsa_key_types[n].prime;
			key_gen_attrs[0].content.ref.length =
				dsa_key_types[n].prime_len;

			key_gen_attrs[1].attributeID = TEE_ATTR_DSA_SUBPRIME;
			key_gen_attrs[1].content.ref.buffer =
				(void *)dsa_key_types[n].sub_prime;
			key_gen_attrs[1].content.ref.length =
				dsa_key_types[n].sub_prime_len;

			key_gen_attrs[2].attributeID = TEE_ATTR_DSA_BASE;
			key_gen_attrs[2].content.ref.buffer =
				(void *)dsa_key_types[n].base;
			key_gen_attrs[2].content.ref.length =
				dsa_key_types[n].base_len;

			key_gen_nb_attrs = 3;
			break;
		}

		break;

	case TEE_TYPE_DH_KEYPAIR:
		prime_len = keysize / 8;
		base_len = keysize / 64;

		if (keysize < 256 || keysize > 2048) {
			EMSG("DH key pair size %" PRIx32 " out of bound",
			     keysize);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		/* The prime and base are gereted randomly */
		TEE_GenerateRandom(dh_prime, prime_len);
		TEE_GenerateRandom(dh_base, base_len);

		/*
		 * WARNING if prime is even, PKHA Exponentiation
		 * generate an error ensure if it will be even
		 * all the time
		 */
		dh_prime[prime_len - 1] |= 1;

		key_gen_attrs[0].attributeID = TEE_ATTR_DH_PRIME;
		key_gen_attrs[0].content.ref.buffer = (void *)dh_prime;
		key_gen_attrs[0].content.ref.length = prime_len;

		key_gen_attrs[1].attributeID = TEE_ATTR_DH_BASE;
		key_gen_attrs[1].content.ref.buffer = (void *)dh_base;
		key_gen_attrs[1].content.ref.length = base_len;

		key_gen_nb_attrs = 2;

		break;

	case TEE_TYPE_ECDSA_KEYPAIR:
		if (keysize < 192 || keysize > 521) {
			EMSG("ECDSA key pair size %" PRIx32 " out of bound",
			     keysize);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		switch (alg_id) {
		case TEE_ALG_ECDSA_P192:
			curve = TEE_ECC_CURVE_NIST_P192;
			break;

		case TEE_ALG_ECDSA_P224:
			curve = TEE_ECC_CURVE_NIST_P224;
			break;

		case TEE_ALG_ECDSA_P256:
			curve = TEE_ECC_CURVE_NIST_P256;
			break;

		case TEE_ALG_ECDSA_P384:
			curve = TEE_ECC_CURVE_NIST_P384;
			break;

		case TEE_ALG_ECDSA_P521:
			curve = TEE_ECC_CURVE_NIST_P521;
			break;

		default:
			EMSG("Can't find curve for ECDSA with algo %" PRIx32,
			     alg_id);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		key_gen_attrs[0].attributeID = TEE_ATTR_ECC_CURVE;
		key_gen_attrs[0].content.value.b = sizeof(int);
		key_gen_attrs[0].content.value.a = curve;
		key_gen_nb_attrs = 1;
		break;

	case TEE_TYPE_ECDH_KEYPAIR:
		if (keysize < 192 || keysize > 521) {
			EMSG("ECDH key pair size %" PRIx32 " out of bound",
			     keysize);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		switch (alg_id) {
		case TEE_ALG_ECDH_P192:
			curve = TEE_ECC_CURVE_NIST_P192;
			break;

		case TEE_ALG_ECDH_P224:
			curve = TEE_ECC_CURVE_NIST_P224;
			break;

		case TEE_ALG_ECDH_P256:
			curve = TEE_ECC_CURVE_NIST_P256;
			break;

		case TEE_ALG_ECDH_P384:
			curve = TEE_ECC_CURVE_NIST_P384;
			break;

		case TEE_ALG_ECDH_P521:
			curve = TEE_ECC_CURVE_NIST_P521;
			break;

		default:
			EMSG("Cannot find curve for ECDH with algo %" PRIx32,
			     alg_id);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		key_gen_attrs[0].attributeID = TEE_ATTR_ECC_CURVE;
		key_gen_attrs[0].content.value.b = sizeof(int);
		key_gen_attrs[0].content.value.a = curve;
		key_gen_nb_attrs = 1;
		break;

	default:
		/*
		 * All the other type of object are support and do not requires
		 * additional parameters for generation
		 */
		break;
	}

	res = TEE_AllocateTransientObject(objType, keysize, &hkey_gen);
	CHECK(res, "TEE_AllocateTransientObject Cipher", {});

	DMSG("hkey_gen %p, keysize %" PRIx32 ", key_gen_nb_attrs %" PRId32,
	     hkey_gen, keysize, key_gen_nb_attrs);

	return res;
}

TEE_Result TA_Generate(uint32_t ParamTypes, TEE_Param Params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t keysize = 0;
	uint32_t exp_ParamTypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						  TEE_PARAM_TYPE_NONE,
						  TEE_PARAM_TYPE_NONE,
						  TEE_PARAM_TYPE_NONE);

	if (ParamTypes != exp_ParamTypes) {
		EMSG("Parameter type differ: %8.8x instead of %8.8x",
		     ParamTypes, exp_ParamTypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	keysize = Params[0].value.a;

	TEE_ResetTransientObject(hkey_gen);

	DMSG("hkey_gen %p, keysize %" PRIx32 ", key_gen_nb_attrs %" PRId32,
	     hkey_gen, keysize, key_gen_nb_attrs);

	res = TEE_GenerateKey(hkey_gen, keysize, key_gen_attrs,
			      key_gen_nb_attrs);
	CHECK(res, "TEE_GenerateKey", {});

	return res;
}

void TA_FreeGen(void)
{
	TEE_FreeTransientObject(hkey_gen);
	hkey_gen = TEE_HANDLE_NULL;
	memset(key_gen_attrs, 0, sizeof(key_gen_attrs));
	key_gen_nb_attrs = 0;
}
