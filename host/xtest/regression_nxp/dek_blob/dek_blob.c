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

#include <pta_dek_blob.h>

/* Structure to represent a DEK blob resulting of an encapsulation */
struct dekblob {
	/* Header of the DEK blob */
	struct hab_dek_blob_header header;
	/* Array for the blob of data encapsulated */
	uint8_t blob[];
};

/* Structure to represent pages and partition of Secure Memory to use */
struct sm_config {
	unsigned int first_page_to_use;
	unsigned int additional_pages;
	unsigned int partition_to_use;
};

enum sm_params {
	DEFAULT_START_PAGE = 3,
	INVALID_START_PAGE = 20,
	DEFAULT_ADD_PAGES = 1,
	INVALID_ADD_PAGES = 20,
	DEFAULT_PARTITION = 1,
	NOT_OWN_PARTITION = 0,
	INVALID_PARTITION = 20,
};

/* Structure to hold parameter of a DEK blob generation */
struct dek_blob_gen_st {
	const char *const fmt; /* Description of the test */
	size_t key_size;       /* Size of the key to use */
	unsigned int iteration; /* Number of test iteration */
	/* Secure memory configuration to use */
	const struct sm_config *sm_config;
	size_t padding;	  /* Extra space to use for the output buffer */
	uint32_t exp_res; /* Expected result of generation */
};

/* Memory space of the component of a DEK blob */
#define BLOB_PADDING	48
#define DEK_HEADER_SIZE 8
#define DEKBLOB_PADDING (BLOB_PADDING + DEK_HEADER_SIZE)

/* Macro to create struct dek_blob_gen_st object */
#define DEK_BLOB_ST(_str, _key_size, _iteration, _sm_config, _padding, \
		    _exp_res) \
	{ \
		(_str), (_key_size), ( _iteration), (_sm_config), (_padding), \
		(_exp_res) \
	}

#define DEK_BLOB(_str, _key_size, _iteration) \
	DEK_BLOB_ST((_str), (_key_size), (_iteration), NULL, DEKBLOB_PADDING, \
		    TEEC_SUCCESS)

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

static size_t dekblob_create_header(struct hab_dek_blob_header *header,
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
			   size_t key_size, const struct sm_config *sm_config,
			   size_t out_buffer_size, uint32_t exp_res)
{
	struct hab_dek_blob_header exp_header = {};
	struct dekblob *dekblob_out = NULL;
	uint8_t *key = NULL;
	size_t exp_dek_blob_size = 0;
	const uint8_t key_byte_value = 0xBA;

	TEEC_Operation dek_op = TEEC_OPERATION_INITIALIZER;
	TEEC_Operation sm_op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t ret_orig = 0;
	uint32_t param2_type = 0;
	uint32_t param3_type = 0;

	/* Allocate memory for random key and DEK blob */
	dekblob_out = calloc(1, out_buffer_size);
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

	memset(key, key_byte_value, key_size);

	/* Create the DEK blob calling the PTA to encapsulate the random key */
	dek_op.params[0].tmpref.buffer = (void *)key;
	dek_op.params[0].tmpref.size = key_size;

	dek_op.params[1].tmpref.buffer = (void *)dekblob_out;
	dek_op.params[1].tmpref.size = out_buffer_size;

	if (sm_config) {
		dek_op.params[2].value.a = sm_config->first_page_to_use;
		dek_op.params[2].value.b = sm_config->additional_pages;
		dek_op.params[3].value.a = sm_config->partition_to_use;

		param2_type = TEEC_VALUE_INPUT;
		param3_type = TEEC_VALUE_INPUT;
	} else {
		/* Backward compatibility */
		param2_type = TEEC_NONE;
		param3_type = TEEC_NONE;
	}

	dek_op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					     TEEC_MEMREF_TEMP_OUTPUT,
					     param2_type, param3_type);

	res = TEEC_InvokeCommand(db_session, PTA_DEK_CMD_BLOB_ENCAPSULATE,
				 &dek_op, &ret_orig);
	if (!ADBG_EXPECT_TEEC_RESULT(c, exp_res, res)) {
		Do_ADBG_Log("DEK operation returned unexpected value");
		goto out;
	}

	/* If the encapsulation did not expect to succed, returns */
	if (exp_res != TEEC_SUCCESS)
		goto out;

	if (sm_config) {
		/* Free the partition which was used */
		sm_op.params[0].value.a = sm_config->partition_to_use;
		sm_op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						    TEEC_NONE, TEEC_NONE);
		res = TEEC_InvokeCommand(db_session, PTA_DEK_CMD_FREE_PARTITION,
					 &sm_op, &ret_orig);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
			Do_ADBG_Log("Failed to free SM partition %d",
				    sm_config->partition_to_use);
			goto out;
		}
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
			dekblob_create(c, &db_session, st->key_size,
				       st->sm_config,
				       st->key_size + st->padding, st->exp_res);
		}

		Do_ADBG_EndSubCase(c, "Generation using %s", st->fmt);
	}

	TEEC_CloseSession(&db_session);
}

ADBG_CASE_DEFINE(regression_nxp, 1001, nxp_dek_blob_1001,
		 "Test TEE DEK Blob generation");
