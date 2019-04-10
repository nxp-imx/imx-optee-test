// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 NXP
 */

#include "xtest_test.h"
#include "xtest_helpers.h"

#include <ta_crypt.h>
#include <ta_crypt_nxp.h>

#ifdef CFG_BLOB_PTA
#include <pta_blob.h>
#endif

const TEEC_UUID crypt_nxp_user_ta_uuid = TA_CRYPT_NXP_UUID;

static __maybe_unused TEEC_Result ta_crypt_cmd_rng(ADBG_Case_t *c,
		void *buf, size_t blen)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	res = xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig);
	if (res != TEEC_SUCCESS)
		return res;

	op.params[0].tmpref.buffer = buf;
	op.params[0].tmpref.size = blen;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&session,
		TA_CRYPT_CMD_RANDOM_NUMBER_GENEREATE, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, blen, ==,
					   op.params[0].tmpref.size);

	TEEC_CloseSession(&session);

	return res;
}

#ifdef CFG_BLOB_PTA
static void test_blob_nxp001(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

	uint8_t origin_data[45] = { 0 };
	uint8_t result_data[45] = { 0 };

	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_nxp_user_ta_uuid, NULL,
					&ret_orig)))
		return;

	/* Origin data is a random number */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_rng(c, origin_data, sizeof(origin_data))))
		goto out;

	/*
	 * Prepare the data to encapsulate in RED
	 */
	// Blob Type
	op.params[0].value.a = PTA_BLOB_RED;
	// Input origin data
	op.params[1].tmpref.buffer = origin_data;
	op.params[1].tmpref.size   = sizeof(origin_data);
	// Output result data
	op.params[2].tmpref.buffer = result_data;
	op.params[2].tmpref.size   = sizeof(result_data);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE);

	Do_ADBG_BeginSubCase(c, "Blob Test Encaps Params");

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session,
					TA_CRYPT_CMD_BLOB_TEST_PARAM_ENCAPS,
					&op,
					&ret_orig)))
		goto out;

	(void)ADBG_EXPECT_BUFFER(c,
			origin_data, sizeof(origin_data),
			result_data, sizeof(result_data));

	Do_ADBG_EndSubCase(c, NULL);
	Do_ADBG_BeginSubCase(c, "Blob Test Decaps Params");

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session,
					TA_CRYPT_CMD_BLOB_TEST_PARAM_DECAPS,
					&op,
					&ret_orig)))
		goto out;

	(void)ADBG_EXPECT_BUFFER(c,
			origin_data, sizeof(origin_data),
			result_data, sizeof(result_data));

	Do_ADBG_EndSubCase(c, NULL);
	Do_ADBG_BeginSubCase(c, "Blob Test Encaps/Decaps");

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session,
					TA_CRYPT_CMD_BLOB_TESTS,
					&op,
					&ret_orig)))
		goto out;

	(void)ADBG_EXPECT_BUFFER(c,
			origin_data, sizeof(origin_data),
			result_data, sizeof(result_data));

out:
	Do_ADBG_EndSubCase(c, NULL);
	TEEC_CloseSession(&session);
}

ADBG_CASE_DEFINE(regression, nxp001, test_blob_nxp001,
		"Test Internal Blob Encapsulation/Decapsulation");
#endif
