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

#include <pta_digprog.h>

static void digprog_pta(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_UUID uuid = PTA_DIGPROG_UUID;
	TEEC_Session session = {};
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	res = xtest_teec_open_session(&session, &uuid, NULL, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log("Skip test, PTA for DIGPROG not found");
		return;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
		Do_ADBG_Log("Failed to open TA for DIGPROG");
		return;
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&session, 0, &op, &ret_orig);

	ADBG_EXPECT_TEEC_RESULT(c, TEEC_SUCCESS, res);
	ADBG_EXPECT_TRUE(c, op.params[0].value.a != 0);

	Do_ADBG_Log("i.MX Platform Digprog 0x%" PRIx32, op.params[0].value.a);

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression_nxp, 0011, digprog_pta, "Test i.MX DIGPROG PTA");
