// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019, NXP
 */

/*
 * Trusted Application Entry Points
 */
/* Global Includes */
#include <tee_ta_api.h>

/* Local Includes */
#include "blob_taf.h"
#include "ta_crypt_nxp.h"

/* Called each time a new instance is created */
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

/* Called each time an instance is destroyed */
void TA_DestroyEntryPoint(void)
{
}

/* Called each time a session is opened */
TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes,
				    TEE_Param pParams[4],
				    void **ppSessionContext)
{
	(void)nParamTypes;
	(void)pParams;
	(void)ppSessionContext;
	return TEE_SUCCESS;
}

/* Called each time a session is closed */
void TA_CloseSessionEntryPoint(void *pSessionContext)
{
	(void)pSessionContext;
}

/* Called when a command is invoked */
TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
				      uint32_t nCommandID, uint32_t nParamTypes __maybe_unused,
				      TEE_Param pParams[4] __maybe_unused)
{
	(void)pSessionContext;


	switch (nCommandID) {
#ifdef CFG_BLOB_PTA
	case TA_CRYPT_CMD_BLOB_TEST_PARAM_ENCAPS:
		return blob_test_param_encaps(nParamTypes, pParams);
	case TA_CRYPT_CMD_BLOB_TEST_PARAM_DECAPS:
		return blob_test_param_decaps(nParamTypes, pParams);
	case TA_CRYPT_CMD_BLOB_TESTS:
		return blob_tests(nParamTypes, pParams);
#endif
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

