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

		Do_ADBG_Log("Encrypt incremental %zu", inc);
		for (off = 0; off < (SIZE_CTR_MSG - inc); off += inc) {
			out_size = inc;
			res = ta_crypt_cipher_update(c, &session, op, &msg[off],
						     inc, &cipher[off],
						     &out_size);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
				goto out;
		}

		Do_ADBG_Log("Final Encrypt incremental %zu", inc);
		out_size = SIZE_CTR_MSG - off;
		res = ta_crypt_cipher_final(c, &session, op, &msg[off],
					    SIZE_CTR_MSG - off, &cipher[off],
					    &out_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

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

		Do_ADBG_Log("Decrypt incremental %zu", inc);
		for (off = 0; off < (SIZE_CTR_MSG - inc); off += inc) {
			out_size = inc;

			res = ta_crypt_cipher_update(c, &session, op,
						     &cipher[off], inc,
						     &de_msg[off], &out_size);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
				goto out;
		}

		Do_ADBG_Log("Final Decrypt incremental %zu", inc);
		out_size = SIZE_CTR_MSG - off;
		res = ta_crypt_cipher_final(c, &session, op, &cipher[off],
					    SIZE_CTR_MSG - off, &de_msg[off],
					    &out_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

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
