// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 */

#include <assert.h>
#include <pta_i2c_rtc_test.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xtest_helpers.h"
#include "xtest_test.h"

#include <utee_defines.h>
#include <util.h>

static TEEC_Result run_test_suite(ADBG_Case_t *c, TEEC_Session *s)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
			TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, PTA_CMD_I2C_RTC_RUN_TEST_SUITE, &op,
			&ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
				ret_orig);
	}

	return res;
}

static void nxp_peripheral_i2c_001(ADBG_Case_t *c)
{
	TEEC_Result res = TEE_ERROR_GENERIC;
	TEEC_Session session = { };

	const TEEC_UUID pta_ls_i2c_rtc_test_uuid = PTA_LS_I2C_RTC_TEST_SUITE_UUID;
	uint32_t ret_orig = 0;

	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_ls_i2c_rtc_test_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log("regression_nxp 0006 - skip test, PTA not found");
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = run_test_suite(c, &session);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	TEEC_CloseSession(&session);
}

ADBG_CASE_DEFINE(regression_nxp, 0006, nxp_peripheral_i2c_001,
		"Test LS I2C driver with RTC clock (Will take around 10 Seconds)");
