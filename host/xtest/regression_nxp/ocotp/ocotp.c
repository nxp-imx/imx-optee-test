// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 */
#include <stdlib.h>
#include <stdio.h>
#include "xtest_helpers.h"
#include "xtest_test.h"
#include <utee_defines.h>
#include <util.h>
#include <string.h>

#include <pta_ocotp.h>

#define UID_TC(_sz, _exp_res) \
	{ \
		.uid_size = (_sz), .exp_res = (_exp_res), \
	}

struct chip_uid_test_case {
	size_t uid_size;
	TEEC_Result exp_res;
};

static const struct chip_uid_test_case chip_uid_tc[] = {
	UID_TC(0, TEEC_ERROR_BAD_PARAMETERS),
	UID_TC(-1, TEEC_ERROR_OUT_OF_MEMORY),
	UID_TC(1, TEEC_ERROR_BAD_PARAMETERS),
	UID_TC(7, TEEC_ERROR_BAD_PARAMETERS),
	UID_TC(8, TEEC_SUCCESS),
	UID_TC(9, TEEC_ERROR_BAD_PARAMETERS),
	UID_TC(16, TEEC_ERROR_BAD_PARAMETERS),
	UID_TC(255, TEEC_ERROR_BAD_PARAMETERS),
};

static void chip_uid(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_UUID uuid = PTA_OCOTP_UUID;
	TEEC_Session session = {};
	uint32_t ret_orig = 0;
	unsigned int i = 0;
	unsigned int j = 0;

	Do_ADBG_BeginSubCase(c, "Test i.MX Chip IUD read");

	res = xtest_teec_open_session(&session, &uuid, NULL, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log("Skip test, PTA for OCOTP not found");
		goto err;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		Do_ADBG_Log("Failed to open TA for OCOTP");
		goto err;
	}

	for (i = 0; i < ARRAY_SIZE(chip_uid_tc); i++) {
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		const struct chip_uid_test_case *tc = &chip_uid_tc[i];
		uint8_t val[8] = {};

		Do_ADBG_BeginSubCase(c, "Request UID size %zu", tc->uid_size);

		op.params[0].tmpref.size = tc->uid_size;
		op.params[0].tmpref.buffer = val;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE,
						 TEEC_NONE);

		res = TEEC_InvokeCommand(&session, PTA_OCOTP_CHIP_UID, &op,
					 &ret_orig);

		if (!ADBG_EXPECT_TEEC_RESULT(c, tc->exp_res, res))
			goto err;

		if (res == TEEC_SUCCESS) {
			printf("Chip UID: ");
			for (j = 0; j < ARRAY_SIZE(val); j++)
				printf("%02x", val[j]);
			printf("\n");
		}

		Do_ADBG_EndSubCase(c, "Request UID size %zu", tc->uid_size);
	}

err:
	Do_ADBG_EndSubCase(c, "Test i.MX Chip IUD read");
	TEEC_CloseSession(&session);
}

#define FUSE_READ_TC(_b, _w, _exp_res) \
	{ \
		.bank = (_b), .word = (_w), .exp_res = (_exp_res), \
	}

struct fuse_read_test_case {
	unsigned int bank;
	unsigned int word;
	TEEC_Result exp_res;
};

static const struct fuse_read_test_case fuse_read_tc[] = {
	FUSE_READ_TC(0, 1, TEEC_SUCCESS),
	FUSE_READ_TC(0, 2, TEEC_SUCCESS),
	FUSE_READ_TC(-1, -1, TEEC_ERROR_BAD_PARAMETERS),
	FUSE_READ_TC(1, 128, TEEC_ERROR_BAD_PARAMETERS),
	FUSE_READ_TC(128, 1, TEEC_ERROR_BAD_PARAMETERS),
};

static void fuse_read(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_UUID uuid = PTA_OCOTP_UUID;
	TEEC_Session session = {};
	uint32_t ret_orig = 0;
	unsigned int i = 0;

	Do_ADBG_BeginSubCase(c, "Test i.MX OCOTP fuse read");

	res = xtest_teec_open_session(&session, &uuid, NULL, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log("Skip test, PTA for OCOTP not found");
		goto err;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		Do_ADBG_Log("Failed to open TA for OCOTP");
		goto err;
	}

	for (i = 0; i < ARRAY_SIZE(fuse_read_tc); i++) {
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		const struct fuse_read_test_case *tc = &fuse_read_tc[i];

		Do_ADBG_BeginSubCase(c, "Request fuse read bank %d word %d",
				     tc->bank, tc->word);

		op.params[0].value.a = tc->bank;
		op.params[0].value.b = tc->word;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_VALUE_OUTPUT, TEEC_NONE,
						 TEEC_NONE);

		res = TEEC_InvokeCommand(&session, PTA_OCOTP_READ_FUSE, &op,
					 &ret_orig);

		if (!ADBG_EXPECT_TEEC_RESULT(c, tc->exp_res, res))
			goto err;

		if (res == TEEC_SUCCESS)
			Do_ADBG_Log("Fuse: 0x%X", op.params[1].value.a);

		Do_ADBG_EndSubCase(c, "Request fuse read bank %d word %d",
				   tc->bank, tc->word);
	}

err:
	Do_ADBG_EndSubCase(c, "Test i.MX OCOTP fuse read");
	TEEC_CloseSession(&session);
}

static void ocotp_pta(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_UUID uuid = PTA_OCOTP_UUID;
	TEEC_Session session = {};
	uint32_t ret_orig = 0;

	Do_ADBG_BeginSubCase(c, "Open OCOTP PTA");

	res = xtest_teec_open_session(&session, &uuid, NULL, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log("Skip test, PTA for OCOTP not found");
		return;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		Do_ADBG_Log("Failed to open TA for OCOTP");
		return;
	}

	TEEC_CloseSession(&session);

	Do_ADBG_EndSubCase(c, "Open OCOTP PTA");

	chip_uid(c);
	fuse_read(c);
}
ADBG_CASE_DEFINE(regression_nxp, 0010, ocotp_pta, "Test i.MX OCOTP PTA");
