// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 NXP
 */
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <utee_defines.h>
#include <util.h>
#include "xtest_helpers.h"
#include "xtest_test.h"

#include <pta_imx_trusted_arm_ce.h>

#define AES_BLOCK_SIZE 16
#define ALGO_AES_CBC 0x10000110
#define ALGO_AES_XTS 0x10000410

static void *map_memory(off_t offset, size_t len)
{
	/* Truncate offset to a multiple of the page size, or mmap will fail. */
	size_t pagesize = sysconf(_SC_PAGE_SIZE);
	off_t page_base = (offset / pagesize) * pagesize;
	off_t page_offset = offset - page_base;

	unsigned char *mem = mmap(NULL, page_offset + len,
				  PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, page_base);
	if (mem == MAP_FAILED) {
		perror("Can't map memory");
		return NULL;
	}

	return mem;
}

static ssize_t read_random(void *in, size_t rsize)
{
	static int rnd;
	ssize_t rnd_size = 0;

	if (!rnd) {
		rnd = open("/dev/urandom", O_RDONLY);
		if (rnd < 0) {
			perror("open");
			return 1;
		}
	}
	rnd_size = read(rnd, in, rsize);
	if (rnd_size < 0) {
		perror("read");
		return 1;
	}
	if ((size_t)rnd_size != rsize)
		printf("read: requested %zu bytes, got %zd\n", rsize, rnd_size);

	return 0;
}

static uint8_t *serialize_memref(uint8_t *buffer, paddr_t pa, size_t sz)
{
	memcpy(buffer, &pa, sizeof(paddr_t));
	buffer += sizeof(paddr_t);
	memcpy(buffer, &sz, sizeof(size_t));
	buffer += sizeof(size_t);
	return buffer;
}

static TEEC_Result pta_set_key(TEEC_Session *session, uint32_t cmd_id,
			       size_t salt_length, uint32_t key_id)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint8_t *salt = NULL;

	salt = malloc(salt_length);
	if (!salt)
		return TEEC_ERROR_OUT_OF_MEMORY;

	if (read_random(salt, salt_length))
		goto out;

	op.params[0].tmpref.buffer = salt;
	op.params[0].tmpref.size = salt_length;
	op.params[1].value.a = key_id;
	op.params[1].value.b = key_id + 1;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(session, cmd_id, &op, &ret_orig);
out:
	free(salt);

	return res;
}

static TEEC_Result pta_shm_allocate(TEEC_Session *session, size_t length,
				    paddr_t *pa)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	reg_pair_from_64(length, &op.params[0].value.a, &op.params[0].value.b);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(session, PTA_SHM_ALLOCATE, &op, &ret_orig);
	if (res)
		return res;

	*pa = reg_pair_to_64(op.params[1].value.a, op.params[1].value.b);
	if (!*pa)
		return TEEC_ERROR_OUT_OF_MEMORY;

	return TEEC_SUCCESS;
}

static TEEC_Result pta_shm_free(TEEC_Session *session, paddr_t pa)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	reg_pair_from_64(pa, &op.params[0].value.a, &op.params[0].value.b);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	return TEEC_InvokeCommand(session, PTA_SHM_FREE, &op, &ret_orig);
}

static TEEC_Result pta_cipher_cbc(TEEC_Session *session, uint32_t key_id,
				  TEEC_SharedMemory *params, bool encrypt)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	op.params[0].memref.parent = params;
	op.params[0].memref.size = params->size;
	op.params[0].memref.offset = 0;
	op.params[1].value.a = key_id;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE);

	return TEEC_InvokeCommand(session,
				  (encrypt ? PTA_ENCRYPT_CBC : PTA_DECRYPT_CBC),
				  &op, &ret_orig);
}

static TEEC_Result pta_cipher_xts(TEEC_Session *session, uint32_t key_id_1,
				  uint32_t key_id_2, TEEC_SharedMemory *params,
				  bool encrypt)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	op.params[0].memref.parent = params;
	op.params[0].memref.size = params->size;
	op.params[0].memref.offset = 0;
	op.params[1].value.a = key_id_1;
	op.params[1].value.b = key_id_2;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE);

	return TEEC_InvokeCommand(session,
				  (encrypt ? PTA_ENCRYPT_XTS : PTA_DECRYPT_XTS),
				  &op, &ret_orig);
}

static TEEC_Result pta_cipher(TEEC_Session *session, uint32_t alg,
			      size_t key_size, uint32_t key_id,
			      size_t data_length)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	paddr_t pa = 0;
	paddr_t input_pa = 0;
	paddr_t output_pa = 0;
	paddr_t iv_pa = 0;
	TEEC_SharedMemory params = {};
	uint8_t *buffer = NULL;
	uint8_t *input_buffer = NULL;
	uint8_t *output_buffer = NULL;
	uint8_t *iv_buffer = NULL;
	uint8_t *params_buffer = NULL;
	size_t buffer_length = 0;

	buffer_length = ROUNDUP(data_length, 4) * 2 + AES_BLOCK_SIZE;

	res = pta_shm_allocate(session, buffer_length, &pa);
	if (res != TEEC_SUCCESS)
		goto err;

	buffer = map_memory(pa, buffer_length);
	if (!buffer) {
		res = TEEC_ERROR_GENERIC;
		goto err;
	}

	if (read_random(buffer, data_length)) {
		res = TEEC_ERROR_GENERIC;
		goto err;
	}

	input_pa = pa;
	output_pa = pa + ROUNDUP(data_length, 4);
	iv_pa = pa + ROUNDUP(data_length, 4) * 2;
	input_buffer = buffer;
	output_buffer = buffer + ROUNDUP(data_length, 4);
	iv_buffer = buffer + ROUNDUP(data_length, 4) * 2;

	params.size = 3 * (sizeof(paddr_t) + sizeof(size_t));
	params.flags = TEEC_MEM_INPUT;
	res = TEEC_AllocateSharedMemory(&xtest_teec_ctx, &params);
	if (res != TEEC_SUCCESS)
		goto err;

	switch (alg) {
	case ALGO_AES_CBC:
		res = pta_set_key(session, PTA_SET_CBC_KEY, key_size, key_id);
		if (res)
			break;

		params_buffer = serialize_memref(params.buffer,
						 input_pa, data_length);
		params_buffer = serialize_memref(
			params_buffer, output_pa, data_length);
		params_buffer = serialize_memref(params_buffer, iv_pa,
						 AES_BLOCK_SIZE);
		res = pta_cipher_cbc(session, key_id, &params, true);
		if (res)
			break;

		memset(iv_buffer, 0, AES_BLOCK_SIZE);
		params_buffer = serialize_memref(
			params.buffer, output_pa, data_length);
		params_buffer = serialize_memref(
			params_buffer, output_pa, data_length);
		params_buffer = serialize_memref(params_buffer, iv_pa,
						 AES_BLOCK_SIZE);
		res = pta_cipher_cbc(session, key_id, &params, false);
		break;
	case ALGO_AES_XTS:
		res = pta_set_key(session, PTA_SET_XTS_KEY, key_size, key_id);
		if (res)
			break;

		params_buffer = serialize_memref(params.buffer,
						 input_pa, data_length);
		params_buffer = serialize_memref(
			params_buffer, output_pa, data_length);
		params_buffer = serialize_memref(params_buffer, iv_pa,
						 AES_BLOCK_SIZE);
		res = pta_cipher_xts(session, key_id, key_id + 1,
				     &params, true);
		if (res)
			break;

		memset(iv_buffer, 0, AES_BLOCK_SIZE);
		params_buffer = serialize_memref(
			params.buffer, output_pa, data_length);
		params_buffer = serialize_memref(
			params_buffer, output_pa, data_length);
		params_buffer = serialize_memref(params_buffer, iv_pa,
						 AES_BLOCK_SIZE);
		res = pta_cipher_xts(session, key_id, key_id + 1,
				     &params, false);
		break;
	default:
		res = TEEC_ERROR_NOT_SUPPORTED;
		break;
	}

	if (res == TEEC_SUCCESS) {
		if (!memcmp(input_buffer, output_buffer, data_length))
			res = TEEC_ERROR_GENERIC;
	}

err:
	TEEC_ReleaseSharedMemory(&params);
	munmap(buffer, buffer_length);
	pta_shm_free(session, pa);

	return res;
}

#define SK_TC(_sz, _id, _cmd_id, _exp_res)                                \
	{                                                                 \
		.salt_size = (_sz), .key_id = (_id), .cmd_id = (_cmd_id), \
		.exp_res = (_exp_res),                                    \
	}

struct set_key_test_case {
	size_t salt_size;
	uint32_t key_id;
	uint32_t cmd_id;
	TEEC_Result exp_res;
};

static const struct set_key_test_case set_key_tc[] = {
	SK_TC(16, 0x1FFFFFFF, PTA_SET_CBC_KEY, TEEC_SUCCESS),
	SK_TC(32, 0x1FFFFFFF, PTA_SET_CBC_KEY, TEEC_SUCCESS),
	SK_TC(24, 0x1FFFFFFF, PTA_SET_CBC_KEY, TEEC_ERROR_BAD_PARAMETERS),
	SK_TC(12, 0x1FFFFFFF, PTA_SET_CBC_KEY, TEEC_ERROR_BAD_PARAMETERS),
	SK_TC(32, 0x2FFFFFFF, PTA_SET_XTS_KEY, TEEC_SUCCESS),
	SK_TC(64, 0x2FFFFFFF, PTA_SET_XTS_KEY, TEEC_SUCCESS),
	SK_TC(48, 0x2FFFFFFF, PTA_SET_XTS_KEY, TEEC_ERROR_BAD_PARAMETERS),
	SK_TC(16, 0x2FFFFFFF, PTA_SET_XTS_KEY, TEEC_ERROR_BAD_PARAMETERS),
};

static TEEC_Result pta_open_session(TEEC_Session *session)
{
	TEEC_UUID uuid = PTA_TRUSTED_ARM_CE_UUID;

	return xtest_teec_open_session(session, &uuid, NULL, NULL);
}

static void trusted_arm_ce_pta_set_key(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = {};
	unsigned int i = 0;

	res = pta_open_session(&session);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log("Skip test, PTA for TRUSTED ARM CE not found");
		return;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		Do_ADBG_Log("Failed to open TA for TRUSTED ARM CE");
		return;
	}

	Do_ADBG_BeginSubCase(c, "Test i.MX Set Key");

	for (i = 0; i < ARRAY_SIZE(set_key_tc); i++) {
		const struct set_key_test_case *tc = &set_key_tc[i];

		Do_ADBG_BeginSubCase(c, "Set Key %d size %zu", tc->key_id,
				     tc->salt_size);

		res = pta_set_key(&session, tc->cmd_id, tc->salt_size,
				  tc->key_id);

		if (!ADBG_EXPECT_TEEC_RESULT(c, tc->exp_res, res))
			goto err;

		Do_ADBG_EndSubCase(c, "Set Key %d size %zu", tc->key_id,
				   tc->salt_size);
	}

	Do_ADBG_EndSubCase(c, "Test i.MX Set Key");
err:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression_nxp, 0012, trusted_arm_ce_pta_set_key,
		 "Test i.MX TRUSTED ARM CE PTA Set Key API");

#define ALLOC_TC(_sz, _exp_res)                             \
	{                                                   \
		.alloc_size = (_sz), .exp_res = (_exp_res), \
	}

struct alloc_test_case {
	size_t alloc_size;
	TEEC_Result exp_res;
};

static const struct alloc_test_case alloc_tc[] = {
	ALLOC_TC(8192, TEEC_SUCCESS),
	ALLOC_TC(4096, TEEC_SUCCESS),
	ALLOC_TC(0, TEEC_ERROR_BAD_PARAMETERS),
};

static void trusted_arm_ce_pta_shm(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = {};
	unsigned int i = 0;

	res = pta_open_session(&session);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log("Skip test, PTA for TRUSTED ARM CE not found");
		return;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		Do_ADBG_Log("Failed to open TA for TRUSTED ARM CE");
		return;
	}

	Do_ADBG_BeginSubCase(c, "Test i.MX Allocate static shm");

	for (i = 0; i < ARRAY_SIZE(alloc_tc); i++) {
		const struct alloc_test_case *tc = &alloc_tc[i];
		paddr_t pa = 0;

		Do_ADBG_BeginSubCase(c, "Alloc size %zu", tc->alloc_size);

		res = pta_shm_allocate(&session, tc->alloc_size, &pa);
		if (!ADBG_EXPECT_TEEC_RESULT(c, tc->exp_res, res))
			goto err;

		pta_shm_free(&session, pa);

		Do_ADBG_EndSubCase(c, "Alloc size %zu", tc->alloc_size);
	}

	Do_ADBG_EndSubCase(c, "Test i.MX Allocate static shm");
err:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression_nxp, 0013, trusted_arm_ce_pta_shm,
		 "Test i.MX TRUSTED ARM CE PTA Allocate shm API");

static void trusted_arm_ce_pta_free_shm(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = {};

	res = pta_open_session(&session);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log("Skip test, PTA for TRUSTED ARM CE not found");
		return;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		Do_ADBG_Log("Failed to open TA for TRUSTED ARM CE");
		return;
	}

	Do_ADBG_BeginSubCase(c, "Test i.MX Free static shm");

	res = pta_shm_free(&session, 0);
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_BAD_PARAMETERS, res))
		goto err;

	Do_ADBG_EndSubCase(c, "Test i.MX Free static shm");
err:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression_nxp, 0014, trusted_arm_ce_pta_free_shm,
		 "Test i.MX TRUSTED ARM CE PTA Free shm API");

#define CIPHER_TC(_alg, _sz, _id, _len, _exp_res)                   \
	{                                                           \
		.algo = (_alg), .key_size = (_sz), .key_id = (_id), \
		.data_length = (_len), .exp_res = (_exp_res),       \
	}

struct cipher_test_case {
	unsigned int algo;
	size_t key_size;
	uint32_t key_id;
	size_t data_length;
	TEEC_Result exp_res;
};

static const struct cipher_test_case cipher_tc[] = {
	CIPHER_TC(ALGO_AES_CBC, 16, 0x1FFFFFFF, 4096, TEEC_SUCCESS),
	CIPHER_TC(ALGO_AES_CBC, 32, 0x2FFFFFFF, 4096, TEEC_SUCCESS),
	CIPHER_TC(ALGO_AES_XTS, 32, 0x3FFFFFFF, 4096, TEEC_SUCCESS),
	CIPHER_TC(ALGO_AES_XTS, 64, 0x5FFFFFFF, 4096, TEEC_SUCCESS),
};

static void trusted_arm_ce_pta_cipher(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = {};
	unsigned int i = 0;

	res = pta_open_session(&session);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log("Skip test, PTA for TRUSTED ARM CE not found");
		return;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		Do_ADBG_Log("Failed to open TA for TRUSTED ARM CE");
		return;
	}

	Do_ADBG_BeginSubCase(c, "Test i.MX Cipher");

	for (i = 0; i < ARRAY_SIZE(cipher_tc); i++) {
		const struct cipher_test_case *tc = &cipher_tc[i];

		Do_ADBG_BeginSubCase(c, "Cipher key size %zu data_length %zu",
				     tc->key_size, tc->data_length);

		res = pta_cipher(&session, tc->algo, tc->key_size, tc->key_id,
				 tc->data_length);

		if (!ADBG_EXPECT_TEEC_RESULT(c, tc->exp_res, res))
			goto err;

		Do_ADBG_EndSubCase(c, "Cipher key size %zu data_length %zu",
				   tc->key_size, tc->data_length);
	}

	Do_ADBG_EndSubCase(c, "Test i.MX Cipher");
err:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression_nxp, 0015, trusted_arm_ce_pta_cipher,
		 "Test i.MX TRUSTED ARM CE PTA Cipher API");

#define STRESS_TC(_alg, _sz, _id, _len, _name)                      \
	{                                                           \
		.algo = (_alg), .key_size = (_sz), .key_id = (_id), \
		.data_length = (_len), .sub_test_name = (_name)     \
	}

struct stress_test_case {
	unsigned int algo;
	size_t key_size;
	uint32_t key_id;
	size_t data_length;
	const char *sub_test_name;
};

static const struct stress_test_case stress_tc[] = {
	/* Shm stress test */
	STRESS_TC(0, 0, 0, 512, "Shared memory Stress test"),
	STRESS_TC(0, 0, 0, 1024, "Shared memory Stress test"),
	STRESS_TC(0, 0, 0, 2048, "Shared memory Stress test"),
	STRESS_TC(0, 0, 0, 4096, "Shared memory Stress test"),
	/* Set Key stress test */
	STRESS_TC(ALGO_AES_CBC, 16, 0x1FFFFFFF, 0, "Set Key Stress test"),
	STRESS_TC(ALGO_AES_CBC, 32, 0x2FFFFFFF, 0, "Set Key Stress test"),
	STRESS_TC(ALGO_AES_XTS, 32, 0x3FFFFFFF, 0, "Set Key Stress test"),
	STRESS_TC(ALGO_AES_XTS, 64, 0x5FFFFFFF, 0, "Set Key Stress test"),
	/* Cipher stress test */
	STRESS_TC(ALGO_AES_CBC, 16, 0x1FFFFFFF, 8192, "Cipher Stress test"),
	STRESS_TC(ALGO_AES_CBC, 32, 0x2FFFFFFF, 4096, "Cipher Stress test"),
	STRESS_TC(ALGO_AES_XTS, 32, 0x3FFFFFFF, 8192, "Cipher Stress test"),
	STRESS_TC(ALGO_AES_XTS, 64, 0x5FFFFFFF, 4096, "Cipher Stress test"),
};

struct trusted_arm_ce_pta_thread_arg {
	ADBG_Case_t *case_t;
	const struct stress_test_case *tc;
	TEEC_Session session;
};

#define TEST_LOOP 5000
static void *trusted_arm_ce_pta_thread(void *arg)
{
	struct trusted_arm_ce_pta_thread_arg *a = arg;
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Session *sess = &a->session;
	const struct stress_test_case *tc = a->tc;
	paddr_t pa = 0;
	uint32_t key_id = tc->key_id;
	size_t key_size = tc->key_size;
	size_t data_length = tc->data_length;
	unsigned int i = 0;
	unsigned int n_shm = 0;
	unsigned int n_set_key = 0;
	unsigned int n_cipher = 0;

	/* No algo defined -> allocation stress test */
	if (!tc->algo) {
		n_shm = TEST_LOOP;
	} else {
		/* No data length defined -> set key stress test */
		if (!tc->data_length)
			n_set_key = TEST_LOOP;
		else {
			/* Otherwise -> cipher stress test */
			n_set_key = 1;
			n_cipher = TEST_LOOP;
		}
	}

	for (i = 0; i < n_set_key; i++) {
		switch (tc->algo) {
		case ALGO_AES_CBC:
			res = pta_set_key(sess, PTA_SET_CBC_KEY, key_size,
					  key_id);
			break;
		case ALGO_AES_XTS:
			res = pta_set_key(sess, PTA_SET_XTS_KEY, key_size,
					  key_id);
			break;
		default:
			res = TEEC_ERROR_NOT_SUPPORTED;
			break;
		}
		if (res != TEEC_SUCCESS)
			break;
	}
	if (!ADBG_EXPECT_TEEC_RESULT(a->case_t, TEEC_SUCCESS, res))
		return NULL;

	for (i = 0; i < n_shm; i++) {
		res = pta_shm_allocate(sess, data_length, &pa);
		if (!ADBG_EXPECT_TEEC_RESULT(a->case_t, TEEC_SUCCESS, res))
			return NULL;

		pta_shm_free(sess, pa);
	}

	if (n_cipher) {
		TEEC_SharedMemory params = {};
		uint8_t *params_buffer = NULL;
		size_t buffer_length = 0;
		paddr_t input_pa = 0;
		paddr_t output_pa = 0;
		paddr_t iv_pa = 0;

		buffer_length = ROUNDUP(data_length, 4) * 2 + AES_BLOCK_SIZE;

		res = pta_shm_allocate(sess, buffer_length, &pa);
		if (res != TEEC_SUCCESS)
			goto err;

		input_pa = pa;
		output_pa = pa + ROUNDUP(data_length, 4);
		iv_pa = pa + ROUNDUP(data_length, 4) * 2;

		params.size = 3 * (sizeof(paddr_t) + sizeof(size_t));
		params.flags = TEEC_MEM_INPUT;
		res = TEEC_AllocateSharedMemory(&xtest_teec_ctx, &params);
		if (res != TEEC_SUCCESS)
			goto err;

		params_buffer =
			serialize_memref(params.buffer, input_pa, data_length);
		params_buffer =
			serialize_memref(params_buffer, output_pa, data_length);
		params_buffer =
			serialize_memref(params_buffer, iv_pa, AES_BLOCK_SIZE);

		for (i = 0; i < n_cipher; i++) {
			switch (tc->algo) {
			case ALGO_AES_CBC:
				res = pta_cipher_cbc(sess, key_id, &params,
						     true);
				if (res)
					break;

				res = pta_cipher_cbc(sess, key_id,
						     &params, false);
				break;
			case ALGO_AES_XTS:
				res = pta_cipher_xts(sess, key_id, key_id + 1,
						     &params, true);
				if (res)
					break;

				res = pta_cipher_xts(sess, key_id,
						     key_id + 1,
						     &params, false);
				break;
			default:
				res = TEEC_ERROR_NOT_SUPPORTED;
				break;
			}
			if (res != TEEC_SUCCESS)
				break;
		}
err:
		TEEC_ReleaseSharedMemory(&params);
		pta_shm_free(sess, pa);
	}
	ADBG_EXPECT_TEEC_RESULT(a->case_t, TEEC_SUCCESS, res);

	return NULL;
}

#define NUM_THREADS 4
static void trusted_arm_ce_pta_stress_test(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	struct trusted_arm_ce_pta_thread_arg arg[NUM_THREADS] = {};
	TEEC_UUID uuid = PTA_TRUSTED_ARM_CE_UUID;
	uint32_t orig = 0;
	size_t i = 0;
	size_t n = 0;
	size_t m = 0;
	pthread_t thr[NUM_THREADS] = {};


	for (m = 0; m < NUM_THREADS; m++) {
		res = xtest_teec_open_session(&arg[m].session, &uuid,
					      NULL, &orig);
		if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
			Do_ADBG_Log("Skip test, PTA for TRUSTED ARM CE \
				     not found");
			return;
		}
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
			Do_ADBG_Log("Failed to open TA for TRUSTED ARM CE");
			goto out;
		}
	}

	Do_ADBG_BeginSubCase(c, "Test i.MX Stress test");

	for (i = 0; i < ARRAY_SIZE(stress_tc); i += NUM_THREADS) {
		const struct stress_test_case *tc = &stress_tc[i];

		Do_ADBG_BeginSubCase(c, "%s", tc->sub_test_name);

		for (n = 0; n < NUM_THREADS; n++) {
			arg[n].case_t = c;
			arg[n].tc = tc + n;
			if (!ADBG_EXPECT(
				    c, 0,
				    pthread_create(&thr[n], NULL,
						   trusted_arm_ce_pta_thread,
						   &arg[n])))
				goto out;
		}
		for (n = 0; n < NUM_THREADS; n++)
			ADBG_EXPECT(c, 0, pthread_join(thr[n], NULL));

		Do_ADBG_EndSubCase(c, "%s", tc->sub_test_name);
	}

	Do_ADBG_EndSubCase(c, "Test i.MX Stress test");
out:
	for (i = 0; i < n; i++)
		pthread_join(thr[i], NULL);
	for (i = 0; i < m; i++)
		TEEC_CloseSession(&arg[i].session);
}
ADBG_CASE_DEFINE(regression_nxp, 0016, trusted_arm_ce_pta_stress_test,
		 "Test i.MX TRUSTED ARM CE PTA Cipher stress");
