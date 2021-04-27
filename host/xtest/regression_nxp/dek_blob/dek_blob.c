// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "xtest_helpers.h"
#include "xtest_test.h"

#include <utee_defines.h>
#include <ta_crypt.h>
#include <util.h>

#include <pta_imx_dek_blob.h>

struct dek_blob_header {
	uint8_t tag;	 /* Constant identifying HAB struct: 0x81 */
	uint8_t len_msb; /* Struct length in 8-bit msb */
	uint8_t len_lsb; /* Struct length in 8-bit lsb */
	uint8_t par;	 /* Constant value, HAB version: 0x43 */
	uint8_t mode;	 /* AES encryption CCM mode: 0x66 */
	uint8_t alg;	 /* AES encryption alg: 0x55 */
	uint8_t size;	 /* Unwrapped key value size in bytes */
	uint8_t flg;	 /* Key flags */
};

/* Structure to represent a DEK blob resulting of an encapsulation */
struct dekblob {
	/* Header of the DEK blob */
	struct dek_blob_header header;
	/* Array for the blob of data encapsulated */
	uint8_t blob[];
};

/* Structure to hold parameter of a DEK blob generation */
struct dek_blob_gen_st {
	const char *const fmt; /* Description of the test */
	size_t key_size;       /* Size of the key to use */
	unsigned int iteration; /* Number of test iteration */
};

/* Memory space of the component of a DEK blob */
#define BLOB_PADDING	48
#define DEK_HEADER_SIZE 8
#define DEKBLOB_PADDING (BLOB_PADDING + DEK_HEADER_SIZE)

/* HAB Blob header values */
#define HAB_HDR_TAG	 0x81
#define HAB_HDR_V4	 0x43
#define HAB_HDR_MODE_CCM 0x66
#define HAB_HDR_ALG_AES	 0x55

#define DEK_BLOB(_str, _key_size, _iteration) \
	{ \
		(_str), (_key_size), ( _iteration), \
	}

/*
 * We are checking the error code for operation not supported:
 * - key size not supported -> pass key size
 * - sm not existent -> pass key size
 * - buffer too small -> add param out_buffer_size
 */
static const struct dek_blob_gen_st dek_blob_gen_sts[] = {
	DEK_BLOB("16 bytes key", 16, 100),
	DEK_BLOB("24 bytes key", 24, 100),
	DEK_BLOB("32 bytes key", 32, 100),
};

static size_t dekblob_create_header(struct dek_blob_header *header,
				    size_t key_size)
{
	size_t total_size = key_size + BLOB_PADDING + sizeof(*header);

	header->tag = HAB_HDR_TAG;
	header->len_msb = (total_size >> 8) & 0xff;
	header->len_lsb = total_size & 0xff;
	header->par = HAB_HDR_V4;
	header->mode = HAB_HDR_MODE_CCM;
	header->alg = HAB_HDR_ALG_AES;
	header->size = key_size;
	header->flg = 0;

	return total_size;
}

static void dekblob_create(ADBG_Case_t *c, TEEC_Session *db_session,
			   size_t key_size)
{
	struct dekblob *dekblob_out = NULL;
	uint8_t *key = NULL;
	TEEC_Operation dek_op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t ret_orig = 0;
	struct dek_blob_header exp_header = { };
	const size_t dekblob_out_size = 128;
	size_t exp_dek_blob_size = 0;

	/* Allocate memory for random key and DEK blob */
	dekblob_out = calloc(1, dekblob_out_size);
	if (!ADBG_EXPECT_NOT_NULL(c, dekblob_out)) {
		Do_ADBG_Log("Failed to allocate memory for DEK blob");
		return;
	}

	/* Create key for blob */
	key = malloc(key_size);
	if (!ADBG_EXPECT_NOT_NULL(c, key)) {
		Do_ADBG_Log("Failed to allocate memory for random key");
		goto out;
	}

	memset(key, 0xBA, key_size);

	/* Create the DEK blob calling the PTA to encapsulate the random key */
	dek_op.params[0].tmpref.buffer = (void *)key;
	dek_op.params[0].tmpref.size = key_size;
	dek_op.params[1].tmpref.buffer = (void *)dekblob_out;
	dek_op.params[1].tmpref.size = dekblob_out_size;

	dek_op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					     TEEC_MEMREF_TEMP_OUTPUT,
					     TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(db_session, PTA_IMX_DEK_BLOB_CMD_GENERATE,
				 &dek_op, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		Do_ADBG_Log("DEK operation returned unexpected value");
		goto out;
	}

	/* Create the expected header and getting expecting out size */
	exp_dek_blob_size = dekblob_create_header(&exp_header, key_size);

	/* Verify the size returned */
	if (!ADBG_EXPECT(c, exp_dek_blob_size, dek_op.params[1].tmpref.size)) {
		Do_ADBG_Log("The DEK blob does not have the expected size");
		goto out;
	}

	/* Verify the header */
	if (!ADBG_EXPECT_BUFFER(c, &exp_header, sizeof(exp_header),
				&dekblob_out->header,
				sizeof(dekblob_out->header))) {
		Do_ADBG_Log("The DEK blob header is malformed");
		goto out;
	}

out:
	free(key);
	free(dekblob_out);
}

static void nxp_dek_blob_1001(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t ret_orig = 0;
	TEEC_UUID pta_dekblob = PTA_DEK_BLOB_UUID;
	TEEC_Session db_session = {};
	size_t idx = 0;
	unsigned int itr = 0;

	/* Open PTA for DEK blob, if it fails, skip the test */
	res = xtest_teec_open_session(&db_session, &pta_dekblob, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log(
			"Skip test, pseudo TA for DEK encapsulation not found");
		return;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		Do_ADBG_Log("Failed to open PTA for DEK encapsulation");
		return;
	}

	for (idx = 0; idx < ARRAY_SIZE(dek_blob_gen_sts); idx++) {
		const struct dek_blob_gen_st *st = &dek_blob_gen_sts[idx];

		Do_ADBG_BeginSubCase(c, "Generation using %s", st->fmt);

		for (itr = 0; itr < st->iteration; itr++) {
			dekblob_create(c, &db_session, st->key_size);
		}

		Do_ADBG_EndSubCase(c, "Generation using %s", st->fmt);
	}

	TEEC_CloseSession(&db_session);
}

ADBG_CASE_DEFINE(regression_nxp, 1001, nxp_dek_blob_1001,
		 "Test TEE DEK Blob generation");
