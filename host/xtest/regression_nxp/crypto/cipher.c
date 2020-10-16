// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "nxp_crypto_test_vectors.h"
#include "xtest_helpers.h"
#include "xtest_test.h"

#include <ta_crypt.h>
#include <utee_defines.h>
#include <util.h>

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

ADBG_CASE_DEFINE(regression_nxp, 0001, nxp_crypto_001,
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

ADBG_CASE_DEFINE(regression_nxp, 0002, nxp_crypto_002,
		 "Test TEE cipher AES CTR decrypt byte per byte");

static void nxp_crypto_003(ADBG_Case_t *c)
{
	TEEC_Result res = TEE_ERROR_GENERIC;
	TEEC_Session session = {};
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute key_attr = {};
	size_t key_size = 0;
	size_t out_size = 0;
	uint32_t ret_orig = 0;

	uint8_t *big_input = NULL;
	uint8_t *big_output = NULL;
	uint8_t *dec_input = NULL;
	size_t len_data_ref = 0;

#define BIG_BUFFER_SIZE 133120

	big_input = malloc(BIG_BUFFER_SIZE);
	if (!ADBG_EXPECT_NOT_NULL(c, big_input))
		goto out_free;

	big_output = malloc(BIG_BUFFER_SIZE);
	if (!ADBG_EXPECT_NOT_NULL(c, big_output))
		goto out_free;

	dec_input = malloc(BIG_BUFFER_SIZE);
	if (!ADBG_EXPECT_NOT_NULL(c, dec_input))
		goto out_free;

	Do_ADBG_Log("Allocated big Input buffer @%p - %d bytes", big_input,
		    BIG_BUFFER_SIZE);
	Do_ADBG_Log("Allocated big Output buffer @%p - %d bytes", big_output,
		    BIG_BUFFER_SIZE);
	Do_ADBG_Log("Allocated big Decrypt buffer @%p - %d bytes", dec_input,
		    BIG_BUFFER_SIZE);

	len_data_ref = ARRAY_SIZE(ciph_data_ref);

	for (size_t offset = 0; offset < BIG_BUFFER_SIZE;
	     offset += len_data_ref)
		memcpy(big_input + offset, ciph_data_ref, len_data_ref);

	res = xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
				      &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out_free;

	key_attr.attributeID = TEE_ATTR_SECRET_VALUE;
	key_attr.content.ref.buffer = (void *)ciph_data_aes_key;
	key_attr.content.ref.length = ARRAY_SIZE(ciph_data_aes_key);

	key_size = key_attr.content.ref.length * 8;

	res = ta_crypt_cmd_allocate_operation(c, &session, &op, TEE_ALG_AES_CTR,
					      TEE_MODE_ENCRYPT, key_size);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	res = ta_crypt_cmd_allocate_transient_object(c, &session, TEE_TYPE_AES,
						     key_size, &key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	res = ta_crypt_cmd_populate_transient_object(c, &session, key_handle,
						     &key_attr, 1);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	res = ta_crypt_cmd_set_operation_key(c, &session, op, key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	res = ta_crypt_cipher_init(c, &session, op, ciph_data_128_iv,
				   ARRAY_SIZE(ciph_data_128_iv));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	out_size = BIG_BUFFER_SIZE;
	memset(big_output, 0x55, out_size);
	res = ta_crypt_cipher_final(c, &session, op, big_input, BIG_BUFFER_SIZE,
				    big_output, &out_size);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	res = ta_crypt_cmd_free_operation(c, &session, op);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	/*
	 * Decrypt output cipher generated and verify it with the input
	 * buffer.
	 */
	res = ta_crypt_cmd_allocate_operation(c, &session, &op, TEE_ALG_AES_CTR,
					      TEE_MODE_DECRYPT, key_size);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	res = ta_crypt_cmd_set_operation_key(c, &session, op, key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	res = ta_crypt_cipher_init(c, &session, op, ciph_data_128_iv,
				   ARRAY_SIZE(ciph_data_128_iv));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	out_size = BIG_BUFFER_SIZE;
	memset(dec_input, 0x55, out_size);
	res = ta_crypt_cipher_final(c, &session, op, big_output,
				    BIG_BUFFER_SIZE, dec_input, &out_size);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	res = ta_crypt_cmd_free_operation(c, &session, op);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	(void)ADBG_EXPECT_BUFFER(c, big_input, BIG_BUFFER_SIZE, dec_input,
				 out_size);

out:
	if (key_handle != TEE_HANDLE_NULL) {
		res = ta_crypt_cmd_free_transient_object(c, &session,
							 key_handle);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;
	}

	TEEC_CloseSession(&session);

out_free:
	if (big_input)
		free(big_input);

	if (big_output)
		free(big_output);

	if (dec_input)
		free(dec_input);
}

ADBG_CASE_DEFINE(regression_nxp, 0003, nxp_crypto_003,
		 "Test TEE cipher operations with big buffers");
