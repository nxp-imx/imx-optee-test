// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "xtest_helpers.h"
#include "xtest_test.h"

#include <ta_crypt.h>
#include <utee_defines.h>
#include <util.h>

static const uint8_t ciph_data_128_iv[] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, /* 12345678 */
	0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, /* 9ABCDEF0 */
};

static const uint8_t ciph_data_ref2[] = {
	0x6d, 0x2c, 0x07, 0xe1, 0xfc, 0x86, 0xf9, 0x9c, 0x6e, 0x2a, 0x8f,
	0x65, 0x67, 0x82, 0x8b, 0x42, 0x62, 0xa9, 0xc2, 0x3d, 0x0f, 0x3e,
	0xd8, 0xab, 0x32, 0x48, 0x22, 0x83, 0xc7, 0x97, 0x96, 0xf0, 0xad,
	0xba, 0x1b, 0xcd, 0x37, 0x36, 0x08, 0x49, 0x96, 0x45, 0x2a, 0x91,
	0x7f, 0xae, 0x98, 0x00, 0x5a, 0xeb, 0xe6, 0x1f, 0x9e, 0x91, 0xc3,
};

static const uint8_t ciph_data_out2[] = {
	0x34, 0x5d, 0xeb, 0x1d, 0x67, 0xb9, 0x5e, 0x60, 0x0e, 0x05, 0xca,
	0xd4, 0xc3, 0x2e, 0xc3, 0x81, 0xaa, 0xdb, 0x3e, 0x2c, 0x1e, 0xc7,
	0xe0, 0xfb, 0x95, 0x6d, 0xc3, 0x8e, 0x68, 0x60, 0xcf, 0x05, 0x53,
	0x53, 0x55, 0x66, 0xe1, 0xb1, 0x2f, 0xa9, 0xf8, 0x7d, 0x29, 0x26,
	0x6c, 0xa2, 0x6d, 0xf4, 0x27, 0x23, 0x3d, 0xf0, 0x35, 0xdf, 0x28,
};

static const uint8_t ciph_data_key2[] = { 0x47, 0x13, 0xa7, 0xb2, 0xf9, 0x3e,
					  0xfe, 0x80, 0x9b, 0x42, 0xec, 0xc4,
					  0x52, 0x13, 0xef, 0x9f };

static const uint8_t ciph_data_iv2[] = { 0xeb, 0xfa, 0x19, 0xb0, 0xeb, 0xf3,
					 0xd5, 0x7f, 0xea, 0xbd, 0x4c, 0x4b,
					 0xd0, 0x4b, 0xea, 0x01 };

static TEEC_Result ta_crypt_cipher_init(ADBG_Case_t *c, TEEC_Session *s,
					TEE_OperationHandle oph, const void *iv,
					size_t iv_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	if (iv) {
		op.params[1].tmpref.buffer = (void *)iv;
		op.params[1].tmpref.size = iv_len;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_INPUT,
						 TEEC_NONE, TEEC_NONE);
	} else {
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
	}

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_CIPHER_INIT, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cipher_update(ADBG_Case_t *c, TEEC_Session *s,
					  TEE_OperationHandle oph,
					  const void *src, size_t src_len,
					  void *dst, size_t *dst_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = dst;
	op.params[2].tmpref.size = *dst_len;

	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_CIPHER_UPDATE, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*dst_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_cipher_final(ADBG_Case_t *c, TEEC_Session *s,
					 TEE_OperationHandle oph,
					 const void *src, size_t src_len,
					 void *dst, size_t *dst_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = (void *)dst;
	op.params[2].tmpref.size = *dst_len;

	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_CIPHER_DO_FINAL, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*dst_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_cmd_generate_key(ADBG_Case_t *c, TEEC_Session *s,
					     TEE_ObjectHandle o,
					     uint32_t key_size)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint8_t *buf = NULL;
	size_t blen = 0;

	assert((uintptr_t)o <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)o;
	op.params[0].value.b = key_size;

	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;

	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_GENERATE_KEY, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	free(buf);
	return res;
}

static void nxp_crypto_001(ADBG_Case_t *c)
{
	TEEC_Result res = TEE_ERROR_GENERIC;
	TEEC_Session session = {};
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	uint32_t ret_orig = 0;

	size_t inc = 0;
	size_t off = 0;
	size_t out_size = 0;
	uint32_t key_size = 128;
	uint8_t *msg = NULL;
	uint8_t *cipher = NULL;
	uint8_t *de_msg = NULL;

#define SIZE_CTR_MSG 240

	cipher = malloc(SIZE_CTR_MSG);
	if (!ADBG_EXPECT_NOT_NULL(c, cipher))
		goto out_free;

	msg = malloc(SIZE_CTR_MSG);
	if (!ADBG_EXPECT_NOT_NULL(c, msg))
		goto out_free;

	de_msg = malloc(SIZE_CTR_MSG);
	if (!ADBG_EXPECT_NOT_NULL(c, de_msg))
		goto out_free;

	res = xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
				      &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out_free;

	/* Generate a 128 bits AES key */
	res = ta_crypt_cmd_allocate_transient_object(c, &session, TEE_TYPE_AES,
						     key_size, &key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	res = ta_crypt_cmd_generate_key(c, &session, key_handle, key_size);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	for (inc = 1; inc <= SIZE_CTR_MSG; ++inc) {
		/* Fill message with 'a' */
		memset(msg, 'a', SIZE_CTR_MSG);

		/* Fill cipher with 'U' */
		memset(cipher, 'U', SIZE_CTR_MSG);

		/* Fill decrypted message with 'U' */
		memset(de_msg, 'U', SIZE_CTR_MSG);

		/*
		 * 1st. Encryption
		 */
		res = ta_crypt_cmd_allocate_operation(c, &session, &op,
						      TEE_ALG_AES_CTR,
						      TEE_MODE_ENCRYPT,
						      key_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		res = ta_crypt_cmd_set_operation_key(c, &session, op,
						     key_handle);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		res = ta_crypt_cipher_init(c, &session, op, ciph_data_128_iv,
					   ARRAY_SIZE(ciph_data_128_iv));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		for (off = 0; off < (SIZE_CTR_MSG - inc); off += inc) {
			out_size = inc;
			res = ta_crypt_cipher_update(c, &session, op, &msg[off],
						     inc, &cipher[off],
						     &out_size);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
				Do_ADBG_Log("Encrypt incremental %zu", inc);
				goto out;
			}
		}

		out_size = SIZE_CTR_MSG - off;
		res = ta_crypt_cipher_final(c, &session, op, &msg[off],
					    SIZE_CTR_MSG - off, &cipher[off],
					    &out_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
			Do_ADBG_Log("Final Encrypt incremental %zu", inc);
			goto out;
		}

		res = ta_crypt_cmd_free_operation(c, &session, op);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		/*
		 * 2nd. Encryption
		 */
		res = ta_crypt_cmd_allocate_operation(c, &session, &op,
						      TEE_ALG_AES_CTR,
						      TEE_MODE_DECRYPT,
						      key_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		res = ta_crypt_cmd_set_operation_key(c, &session, op,
						     key_handle);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		res = ta_crypt_cipher_init(c, &session, op, ciph_data_128_iv,
					   ARRAY_SIZE(ciph_data_128_iv));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		for (off = 0; off < (SIZE_CTR_MSG - inc); off += inc) {
			out_size = inc;

			res = ta_crypt_cipher_update(c, &session, op,
						     &cipher[off], inc,
						     &de_msg[off], &out_size);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
				Do_ADBG_Log("Decrypt incremental %zu", inc);
				goto out;
			}
		}

		out_size = SIZE_CTR_MSG - off;
		res = ta_crypt_cipher_final(c, &session, op, &cipher[off],
					    SIZE_CTR_MSG - off, &de_msg[off],
					    &out_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
			Do_ADBG_Log("Final Decrypt incremental %zu", inc);
			goto out;
		}

		res = ta_crypt_cmd_free_operation(c, &session, op);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		/* Compare original message with decrypted message */
		(void)ADBG_EXPECT_BUFFER(c, msg, SIZE_CTR_MSG, de_msg,
					 SIZE_CTR_MSG);
	}

	res = ta_crypt_cmd_free_transient_object(c, &session, key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

out:
	TEEC_CloseSession(&session);

out_free:
	if (cipher)
		free(cipher);
	if (msg)
		free(msg);
	if (de_msg)
		free(de_msg);
}

ADBG_CASE_DEFINE(regression, nxp_001, nxp_crypto_001,
		 "Test TEE cipher AES CTR operation byte incremental in/out");

static void nxp_crypto_002(ADBG_Case_t *c)
{
	TEEC_Result res = TEE_ERROR_GENERIC;
	TEEC_Session session = {};
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute key_attr = {};
	uint32_t ret_orig = 0;

	size_t off = 0;
	size_t out_size = 0;
	uint8_t *de_msg = NULL;
	uint32_t key_size = 0;
	size_t msg_size = ARRAY_SIZE(ciph_data_ref2);

	de_msg = malloc(msg_size);
	if (!ADBG_EXPECT_NOT_NULL(c, de_msg))
		goto out_free;

	res = xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
				      &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out_free;

	key_attr.attributeID = TEE_ATTR_SECRET_VALUE;
	key_attr.content.ref.buffer = (void *)ciph_data_key2;
	key_attr.content.ref.length = ARRAY_SIZE(ciph_data_key2);

	key_size = key_attr.content.ref.length * 8;

	res = ta_crypt_cmd_allocate_transient_object(c, &session, TEE_TYPE_AES,
						     key_size, &key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	res = ta_crypt_cmd_populate_transient_object(c, &session, key_handle,
						     &key_attr, 1);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	res = ta_crypt_cmd_allocate_operation(c, &session, &op, TEE_ALG_AES_CTR,
					      TEE_MODE_DECRYPT, key_size);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	res = ta_crypt_cmd_set_operation_key(c, &session, op, key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	res = ta_crypt_cipher_init(c, &session, op, ciph_data_iv2,
				   ARRAY_SIZE(ciph_data_iv2));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	for (off = 0; off < msg_size; off++) {
		out_size = 1;
		res = ta_crypt_cipher_update(c, &session, op,
					     &ciph_data_out2[off], 1,
					     &de_msg[off], &out_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, out_size, ==, 1))
			goto out;
	}

	res = ta_crypt_cmd_free_operation(c, &session, op);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	/* Compare original message with decrypted message */
	(void)ADBG_EXPECT_BUFFER(c, ciph_data_ref2, msg_size, de_msg, msg_size);

	res = ta_crypt_cmd_free_transient_object(c, &session, key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

out:
	TEEC_CloseSession(&session);

out_free:
	if (de_msg)
		free(de_msg);
}

ADBG_CASE_DEFINE(regression, nxp_002, nxp_crypto_002,
		 "Test TEE cipher AES CTR decrypt byte per byte");
