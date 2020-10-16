// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nxp_crypto_test_vectors.h"
#include "xtest_helpers.h"
#include "xtest_test.h"

#include <ta_crypt.h>
#include <utee_defines.h>
#include <util.h>

#define STATS_UUID                                                             \
	{                                                                      \
		0xd96a5b40, 0xe2c7, 0xb1af,                                    \
		{                                                              \
			0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1b         \
		}                                                              \
	}

#define STATS_CMD_ALLOC_STATS 1

#define TEE_ALLOCATOR_DESC_LENGTH 32
struct memstats {
	char desc[TEE_ALLOCATOR_DESC_LENGTH];
	uint32_t allocated;		  /* Bytes currently allocated */
	uint32_t max_allocated;		  /* Tracks max value of allocated */
	uint32_t size;			  /* Total size for this allocator */
	uint32_t num_alloc_fail;	  /* Number of failed alloc requests */
	uint32_t biggest_alloc_fail;	  /* Size of biggest failed alloc */
	uint32_t biggest_alloc_fail_used; /* Alloc bytes when above occurred */
};

struct memstats_test {
	size_t number;
	size_t diff_ta_crypt;
	struct memstats *start;
	struct memstats *end;
};

static TEEC_Result open_ta_memstats(TEEC_Session *sess)
{
	TEEC_UUID uuid = STATS_UUID;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t ret_orig = 0;

	res = xtest_teec_open_session(sess, &uuid, NULL, &ret_orig);
	if (res != TEEC_SUCCESS)
		Do_ADBG_Log("Memory statistique PTA not loaded");

	return res;
}

static void close_ta_memstats(TEEC_Session *sess, struct memstats_test *stats)
{
	if (stats->start)
		free(stats->start);
	if (stats->end)
		free(stats->end);

	TEEC_CloseSession(sess);
}

static TEEC_Result memstat_start(ADBG_Case_t *c, TEEC_Session *sess,
				 struct memstats_test *stats)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = {};
	struct memstats *mstats = NULL;
	size_t stats_size_bytes = 0;
	size_t n = 0;
	uint32_t ret_orig = 0;

	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
				 TEEC_NONE, TEEC_NONE);

	/* Get the Heap Pool */
	op.params[0].value.a = 1;

	res = TEEC_InvokeCommand(sess, STATS_CMD_ALLOC_STATS, &op, &ret_orig);
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER, res))
		goto end;

	stats_size_bytes = op.params[1].tmpref.size;
	if (!ADBG_EXPECT_TRUE(c, !(stats_size_bytes % sizeof(*stats->start))))
		goto end;

	stats->start = calloc(1, stats_size_bytes);
	if (!ADBG_EXPECT_NOT_NULL(c, stats->start))
		goto end;

	stats->end = calloc(1, stats_size_bytes);
	if (!ADBG_EXPECT_NOT_NULL(c, stats->end))
		goto end;

	mstats = stats->start;
	op.params[1].tmpref.buffer = mstats;
	op.params[1].tmpref.size = stats_size_bytes;
	res = TEEC_InvokeCommand(sess, STATS_CMD_ALLOC_STATS, &op, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto end;

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, op.params[1].tmpref.size, ==,
					  stats_size_bytes))
		goto end;

	stats->number = stats_size_bytes / sizeof(*stats->start);

	for (n = 0; n < stats->number; n++) {
		printf("\n");
		printf("===============================================\n");
		printf("Pool: %*s\n",
		       (int)strnlen(mstats[n].desc, sizeof(mstats[n].desc)),
		       mstats[n].desc);
		printf("Bytes allocated:                       %" PRId32 "\n",
		       mstats[n].allocated);
		printf("Max bytes allocated:                   %" PRId32 "\n",
		       mstats[n].max_allocated);
		printf("Size of pool:                          %" PRId32 "\n",
		       mstats[n].size);
		printf("Number of failed allocations:          %" PRId32 "\n",
		       mstats[n].num_alloc_fail);
		printf("Size of larges allocation failure:     %" PRId32 "\n",
		       mstats[n].biggest_alloc_fail);
		printf("Total bytes allocated at that failure: %" PRId32 "\n",
		       mstats[n].biggest_alloc_fail_used);
		printf("===============================================\n");
	}

end:
	return res;
}

static TEEC_Result memstat_diff_ta_user(ADBG_Case_t *c, TEEC_Session *sess,
					struct memstats_test *stats)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = {};
	struct memstats *mstats = NULL;
	uint32_t ret_orig = 0;

	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
				 TEEC_NONE, TEEC_NONE);

	mstats = stats->end;

	/* Get the Heap Pool */
	op.params[0].value.a = 1;

	op.params[1].tmpref.buffer = mstats;
	op.params[1].tmpref.size = stats->number * sizeof(*stats->end);
	res = TEEC_InvokeCommand(sess, STATS_CMD_ALLOC_STATS, &op, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto end;

	stats->diff_ta_crypt = mstats[0].allocated - stats->start[0].allocated;
end:
	return res;
}

static TEEC_Result memstat_end(ADBG_Case_t *c, TEEC_Session *sess,
			       struct memstats_test *stats)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = {};
	struct memstats *mstats = NULL;
	size_t n = 0;
	uint32_t ret_orig = 0;

	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
				 TEEC_NONE, TEEC_NONE);

	mstats = stats->end;

	/* Get the Heap Pool */
	op.params[0].value.a = 1;

	op.params[1].tmpref.buffer = mstats;
	op.params[1].tmpref.size = stats->number * sizeof(*stats->end);
	res = TEEC_InvokeCommand(sess, STATS_CMD_ALLOC_STATS, &op, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto end;

	/* Remove the TA Crypto global data not freed from the heap */
	mstats[0].allocated -= stats->diff_ta_crypt;
	for (n = 0; n < stats->number; n++) {
		printf("\n");
		printf("===============================================\n");
		printf("Pool: %*s\n",
		       (int)strnlen(mstats[n].desc, sizeof(mstats[n].desc)),
		       mstats[n].desc);
		printf("Bytes allocated:                       %" PRId32 "\n",
		       mstats[n].allocated);
		printf("Max bytes allocated:                   %" PRId32 "\n",
		       mstats[n].max_allocated);
		printf("Size of pool:                          %" PRId32 "\n",
		       mstats[n].size);
		printf("Number of failed allocations:          %" PRId32 "\n",
		       mstats[n].num_alloc_fail);
		printf("Size of larges allocation failure:     %" PRId32 "\n",
		       mstats[n].biggest_alloc_fail);
		printf("Total bytes allocated at that failure: %" PRId32 "\n",
		       mstats[n].biggest_alloc_fail_used);
		printf("===============================================\n");
	}

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, stats->start[0].allocated, ==,
					  stats->end[0].allocated))
		goto end;

end:
	return res;
}

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

static TEEC_Result ta_crypt_mac_init(ADBG_Case_t *c, TEEC_Session *s,
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

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_MAC_INIT, &op, &ret_orig);

	if (res) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_mac_update(ADBG_Case_t *c, TEEC_Session *s,
				       TEE_OperationHandle oph,
				       const void *chunk, size_t chunk_size)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_size;

	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_MAC_UPDATE, &op, &ret_orig);

	if (res) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_mac_final_compute(ADBG_Case_t *c, TEEC_Session *s,
					      TEE_OperationHandle oph,
					      const void *chunk,
					      size_t chunk_len, void *hash,
					      size_t *hash_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_len;

	op.params[2].tmpref.buffer = (void *)hash;
	op.params[2].tmpref.size = *hash_len;

	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_MAC_FINAL_COMPUTE, &op,
				 &ret_orig);

	if (res) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	if (!res)
		*hash_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_generate_key(ADBG_Case_t *c, TEEC_Session *s,
					 TEE_ObjectHandle o, uint32_t key_size)
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

static TEE_Result ta_crypt_set_operation_key2(ADBG_Case_t *c, TEEC_Session *s,
					      TEE_OperationHandle oph,
					      TEE_ObjectHandle key1,
					      TEE_ObjectHandle key2)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	assert((uintptr_t)key1 <= UINT32_MAX);
	op.params[0].value.b = (uint32_t)(uintptr_t)key1;

	assert((uintptr_t)key2 <= UINT32_MAX);
	op.params[1].value.a = (uint32_t)(uintptr_t)key2;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_SET_OPERATION_KEY2, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

struct test_cipher {
	uint32_t algo;
	uint8_t mode;
	size_t key_size;
	size_t blk_size;
	size_t nb_blk;
	size_t nb_blk_inc;
	const uint8_t *iv;
	size_t iv_size;
	uint16_t line;
};

#define MODE(mode)	 TEE_MODE_##mode
#define ALGO(algo)	 TEE_ALG_##algo
#define KEY(algo)	 TEE_ALG_GET_KEY_TYPE(algo, false)
#define BLOCK_SIZE(algo) TEE_##algo##_BLOCK_SIZE

#define TEST_CIPHER_NO_IV(algo, op, key_size, blk_size, nb_blk, nb_blk_inc)    \
	{                                                                      \
		(algo), MODE(op), (key_size), (blk_size), (nb_blk),            \
			(nb_blk_inc), NULL, 0, __LINE__                        \
	}

#define TEST_CIPHER_IV(algo, op, key_size, blk_size, nb_blk, nb_blk_inc, iv)   \
	{                                                                      \
		(algo), MODE(op), (key_size), (blk_size), (nb_blk),            \
			(nb_blk_inc), ciph_data_##iv,                          \
			ARRAY_SIZE(ciph_data_##iv), __LINE__                   \
	}

struct test_cipher ac_cipher[] = {
	/* AES */
	TEST_CIPHER_NO_IV(ALGO(AES_ECB_NOPAD), ENCRYPT, 128, BLOCK_SIZE(AES), 4,
			  2),
	TEST_CIPHER_NO_IV(ALGO(AES_ECB_NOPAD), DECRYPT, 128, BLOCK_SIZE(AES), 4,
			  2),
	TEST_CIPHER_IV(ALGO(AES_CBC_NOPAD), ENCRYPT, 128, BLOCK_SIZE(AES), 4, 2,
		       128_iv),
	TEST_CIPHER_IV(ALGO(AES_CBC_NOPAD), DECRYPT, 128, BLOCK_SIZE(AES), 4, 2,
		       128_iv),
	TEST_CIPHER_IV(ALGO(AES_CTR), ENCRYPT, 128, BLOCK_SIZE(AES), 4, 2,
		       128_iv),
	TEST_CIPHER_IV(ALGO(AES_CTR), DECRYPT, 128, BLOCK_SIZE(AES), 4, 2,
		       128_iv),
	TEST_CIPHER_IV(ALGO(AES_CTS), ENCRYPT, 128, BLOCK_SIZE(AES), 4, 2,
		       128_iv),
	TEST_CIPHER_IV(ALGO(AES_CTS), DECRYPT, 128, BLOCK_SIZE(AES), 4, 2,
		       128_iv),
	TEST_CIPHER_IV(ALGO(AES_XTS), ENCRYPT, 128, BLOCK_SIZE(AES), 4, 2,
		       128_iv),
	TEST_CIPHER_IV(ALGO(AES_XTS), DECRYPT, 128, BLOCK_SIZE(AES), 4, 2,
		       128_iv),
	/* DES */
	TEST_CIPHER_NO_IV(ALGO(DES_ECB_NOPAD), ENCRYPT, 64, BLOCK_SIZE(DES), 4,
			  2),
	TEST_CIPHER_NO_IV(ALGO(DES_ECB_NOPAD), DECRYPT, 64, BLOCK_SIZE(DES), 4,
			  2),
	TEST_CIPHER_IV(ALGO(DES_CBC_NOPAD), ENCRYPT, 64, BLOCK_SIZE(DES), 4, 2,
		       64_iv),
	TEST_CIPHER_IV(ALGO(DES_CBC_NOPAD), DECRYPT, 64, BLOCK_SIZE(DES), 4, 2,
		       64_iv),
	/* DES3 */
	TEST_CIPHER_NO_IV(ALGO(DES3_ECB_NOPAD), ENCRYPT, 128, BLOCK_SIZE(DES),
			  4, 2),
	TEST_CIPHER_NO_IV(ALGO(DES3_ECB_NOPAD), DECRYPT, 128, BLOCK_SIZE(DES),
			  4, 2),
	TEST_CIPHER_IV(ALGO(DES3_CBC_NOPAD), ENCRYPT, 128, BLOCK_SIZE(DES), 4,
		       2, 64_iv),
	TEST_CIPHER_IV(ALGO(DES3_CBC_NOPAD), DECRYPT, 128, BLOCK_SIZE(DES), 4,
		       2, 64_iv),
};

struct test_cipher ac_cipher_mac[] = {
	/* AES */
	TEST_CIPHER_NO_IV(ALGO(AES_CBC_MAC_NOPAD), MAC, 128, BLOCK_SIZE(AES), 4,
			  2),
	TEST_CIPHER_NO_IV(ALGO(AES_CMAC), MAC, 128, BLOCK_SIZE(AES), 4, 2),
	TEST_CIPHER_NO_IV(ALGO(AES_CBC_MAC_PKCS5), MAC, 128, BLOCK_SIZE(AES), 4,
			  2),
	/* DES */
	TEST_CIPHER_NO_IV(ALGO(DES_CBC_MAC_NOPAD), MAC, 64, BLOCK_SIZE(DES), 4,
			  2),
	TEST_CIPHER_NO_IV(ALGO(DES_CBC_MAC_PKCS5), MAC, 64, BLOCK_SIZE(DES), 4,
			  2),
	/* DES3 */
	TEST_CIPHER_NO_IV(ALGO(DES3_CBC_MAC_NOPAD), MAC, 128, BLOCK_SIZE(DES),
			  4, 2),
	TEST_CIPHER_NO_IV(ALGO(DES3_CBC_MAC_PKCS5), MAC, 128, BLOCK_SIZE(DES),
			  4, 2),
};

static void check_cipher_memleak(ADBG_Case_t *c, TEEC_Session *ta_stat_sess,
				 struct memstats_test *stats)
{
	TEEC_Result res = TEE_ERROR_GENERIC;
	TEEC_Session session = {};
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key1_hdl = TEE_HANDLE_NULL;
	TEE_ObjectHandle key2_hdl = TEE_HANDLE_NULL;
	uint32_t ret_orig = 0;
	bool test_full = true;
	uint32_t key_type = 0;
	size_t ciph_size = 0;
	size_t inc_size = 0;
	size_t idx = 0;
	size_t out_size = 0;
	size_t out_off = 0;
	size_t op_key_size = 0;
	size_t key_size = 0;
	uint8_t *in = NULL;
	uint8_t *out = NULL;
	size_t ciph_allocated = 0;

	struct test_cipher *test = ac_cipher;

	for (size_t n = 0; n < ARRAY_SIZE(ac_cipher); n++, test++) {
		test_full = true;
		key_type = KEY(test->algo);
		ciph_size = test->blk_size * test->nb_blk;
		inc_size = test->blk_size * test->nb_blk_inc;

		if (ciph_allocated < ciph_size) {
			if (in)
				free(in);

			ciph_allocated = ciph_size;

			in = malloc(ciph_allocated);
			if (!ADBG_EXPECT_NOT_NULL(c, in))
				goto out;

			if (out)
				free(out);

			out = malloc(ciph_allocated);
			if (!ADBG_EXPECT_NOT_NULL(c, out))
				goto out;

			/* Fill the Message value */
			for (idx = 0; idx < ciph_allocated; idx++)
				in[idx] = idx;
		}

redo_test:
		Do_ADBG_BeginSubCase(c,
				     "%sFull Cipher 0x%" PRIX32
				     " mode %d - line: %u",
				     (test_full) ? "" : "Not ", test->algo,
				     test->mode, test->line);

		res = xtest_teec_open_session(&session, &crypt_user_ta_uuid,
					      NULL, &ret_orig);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		/* Generate a Cipher key(s) */
		key_size = test->key_size;

		/* Remove parity bit size */
		if (key_type == TEE_TYPE_DES || key_type == TEE_TYPE_DES3)
			key_size -= key_size / 8;

		res = ta_crypt_cmd_allocate_transient_object(c, &session,
							     key_type, key_size,
							     &key1_hdl);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		res = ta_crypt_generate_key(c, &session, key1_hdl, key_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		op_key_size = key_size;
		if (test->algo == ALGO(AES_XTS))
			op_key_size *= 2;

		/* Prepare cipher operation encrypt or decrypt */
		res = ta_crypt_cmd_allocate_operation(c, &session, &op,
						      test->algo, test->mode,
						      op_key_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		if (test->algo == ALGO(AES_XTS)) {
			res = ta_crypt_cmd_allocate_transient_object(c,
								     &session,
								     key_type,
								     key_size,
								     &key2_hdl);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
				goto out;

			res = ta_crypt_generate_key(c, &session, key2_hdl,
						    key_size);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
				goto out;

			res = ta_crypt_set_operation_key2(c, &session, op,
							  key1_hdl, key2_hdl);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
				goto out;
		} else {
			res = ta_crypt_cmd_set_operation_key(c, &session, op,
							     key1_hdl);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
				goto out;
		}

		Do_ADBG_Log("Free Key 1 object");
		res = ta_crypt_cmd_free_transient_object(c, &session, key1_hdl);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		if (test->algo == ALGO(AES_XTS)) {
			Do_ADBG_Log("Free Key 2 object");
			res = ta_crypt_cmd_free_transient_object(c, &session,
								 key2_hdl);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
				goto out;
		}

		Do_ADBG_Log("Cipher Init");
		res = ta_crypt_cipher_init(c, &session, op, test->iv,
					   test->iv_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		Do_ADBG_Log("Cipher Update");
		out_size = inc_size;
		res = ta_crypt_cipher_update(c, &session, op, in, inc_size, out,
					     &out_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		if (test_full) {
			Do_ADBG_Log("Cipher Final");
			out_off = out_size;
			out_size = ciph_size - out_size;
			res = ta_crypt_cipher_final(c, &session, op,
						    in + inc_size,
						    ciph_size - inc_size,
						    out + out_off, &out_size);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
				goto out;

			res = ta_crypt_cmd_free_operation(c, &session, op);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
				goto out;
		}

		TEEC_CloseSession(&session);
		session.ctx = NULL;

		res = memstat_end(c, ta_stat_sess, stats);
		(void)ADBG_EXPECT_TEEC_SUCCESS(c, res);

		Do_ADBG_EndSubCase(c, NULL);

		if (test_full) {
			test_full = false;
			goto redo_test;
		}
	}
out:
	if (session.ctx)
		TEEC_CloseSession(&session);

	if (in)
		free(in);
	if (out)
		free(out);
}

static void check_cipher_mac_memleak(ADBG_Case_t *c, TEEC_Session *ta_stat_sess,
				     struct memstats_test *stats)
{
	TEEC_Result res = TEE_ERROR_GENERIC;
	TEEC_Session session = {};
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key1_hdl = TEE_HANDLE_NULL;
	uint32_t ret_orig = 0;
	bool test_full = true;
	uint32_t key_type = 0;
	size_t ciph_size = 0;
	size_t inc_size = 0;
	size_t idx = 0;
	size_t out_size = 0;
	size_t op_key_size = 0;
	size_t key_size = 0;
	uint8_t *in = NULL;
	uint8_t *out = NULL;
	size_t ciph_allocated = 0;

	struct test_cipher *test = ac_cipher_mac;

	for (size_t n = 0; n < ARRAY_SIZE(ac_cipher_mac); n++, test++) {
		test_full = true;
		key_type = KEY(test->algo);
		ciph_size = test->blk_size * test->nb_blk;
		inc_size = test->blk_size * test->nb_blk_inc;

		if (ciph_allocated < ciph_size) {
			if (in)
				free(in);

			ciph_allocated = ciph_size;

			in = malloc(ciph_allocated);
			if (!ADBG_EXPECT_NOT_NULL(c, in))
				goto out;

			if (out)
				free(out);

			out = malloc(ciph_allocated);
			if (!ADBG_EXPECT_NOT_NULL(c, out))
				goto out;

			/* Fill the Message value */
			for (idx = 0; idx < ciph_allocated; idx++)
				in[idx] = idx;
		}

redo_test:
		Do_ADBG_BeginSubCase(c,
				     "%sFull Cipher MAC 0x%" PRIX32
				     " mode %d - line: %u",
				     (test_full) ? "" : "Not ", test->algo,
				     test->mode, test->line);

		res = xtest_teec_open_session(&session, &crypt_user_ta_uuid,
					      NULL, &ret_orig);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		/* Generate a Cipher key(s) */
		key_size = test->key_size;

		/* Remove parity bit size */
		if (key_type == TEE_TYPE_DES || key_type == TEE_TYPE_DES3)
			key_size -= key_size / 8;

		res = ta_crypt_cmd_allocate_transient_object(c, &session,
							     key_type, key_size,
							     &key1_hdl);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		res = ta_crypt_generate_key(c, &session, key1_hdl, key_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		op_key_size = key_size;
		if (test->algo == ALGO(AES_XTS))
			op_key_size *= 2;

		/* Prepare cipher operation encrypt or decrypt */
		res = ta_crypt_cmd_allocate_operation(c, &session, &op,
						      test->algo, test->mode,
						      op_key_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		res = ta_crypt_cmd_set_operation_key(c, &session, op, key1_hdl);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		Do_ADBG_Log("Free Key 1 object");
		res = ta_crypt_cmd_free_transient_object(c, &session, key1_hdl);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		Do_ADBG_Log("Cipher MAC Init");
		res = ta_crypt_mac_init(c, &session, op, test->iv,
					test->iv_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		Do_ADBG_Log("Cipher MAC Update");
		res = ta_crypt_mac_update(c, &session, op, in, inc_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		if (test_full) {
			Do_ADBG_Log("Cipher MAC Final");
			out_size = ciph_size;
			res = ta_crypt_mac_final_compute(c, &session, op,
							 in + inc_size,
							 ciph_size - inc_size,
							 out, &out_size);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
				goto out;

			res = ta_crypt_cmd_free_operation(c, &session, op);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
				goto out;
		}

		TEEC_CloseSession(&session);
		session.ctx = NULL;

		res = memstat_end(c, ta_stat_sess, stats);
		(void)ADBG_EXPECT_TEEC_SUCCESS(c, res);

		Do_ADBG_EndSubCase(c, NULL);

		if (test_full) {
			test_full = false;
			goto redo_test;
		}
	}
out:
	if (session.ctx)
		TEEC_CloseSession(&session);

	if (in)
		free(in);
	if (out)
		free(out);
}

static void nxp_memleak_004(ADBG_Case_t *c)
{
	TEEC_Result res = TEE_ERROR_GENERIC;
	TEEC_Session session = {};
	TEEC_Session ta_stat_sess = {};
	uint32_t ret_orig = 0;
	struct memstats_test stats = {};

	res = open_ta_memstats(&ta_stat_sess);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	/*
	 * Get the current memory statistique
	 */
	res = memstat_start(c, &ta_stat_sess, &stats);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	/*
	 * Open and Close TA Crypto to get the overhead of memory
	 * allocated on the heap but not freed when TA session is
	 * closed (because of TA Global data)
	 */
	res = xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
				      &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	TEEC_CloseSession(&session);
	res = memstat_diff_ta_user(c, &ta_stat_sess, &stats);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	check_cipher_memleak(c, &ta_stat_sess, &stats);

out:
	if (ta_stat_sess.ctx)
		close_ta_memstats(&ta_stat_sess, &stats);
}

ADBG_CASE_DEFINE(regression_nxp, 0004, nxp_memleak_004,
		 "Test TEE Cipher operation memory leak");

static void nxp_memleak_005(ADBG_Case_t *c)
{
	TEEC_Result res = TEE_ERROR_GENERIC;
	TEEC_Session session = {};
	TEEC_Session ta_stat_sess = {};
	uint32_t ret_orig = 0;
	struct memstats_test stats = {};

	res = open_ta_memstats(&ta_stat_sess);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	/*
	 * Get the current memory statistique
	 */
	res = memstat_start(c, &ta_stat_sess, &stats);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	/*
	 * Open and Close TA Crypto to get the overhead of memory
	 * allocated on the heap but not freed when TA session is
	 * closed (because of TA Global data)
	 */
	res = xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
				      &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	TEEC_CloseSession(&session);
	res = memstat_diff_ta_user(c, &ta_stat_sess, &stats);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	check_cipher_mac_memleak(c, &ta_stat_sess, &stats);

out:
	if (ta_stat_sess.ctx)
		close_ta_memstats(&ta_stat_sess, &stats);
}

ADBG_CASE_DEFINE(regression_nxp, 0005, nxp_memleak_005,
		 "Test TEE Cipher MAC operation memory leak");
