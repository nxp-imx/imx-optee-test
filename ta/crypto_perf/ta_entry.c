// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
 */

#include <stdio.h>
#include <string.h>

#include <tee_ta_api.h>
#include <ta_crypto_perf.h>

struct ta_caps ta_crypto_caps;

/*
 * Trusted Application Entry Points
 */

/* Called each time a new instance is created */
TEE_Result TA_CreateEntryPoint(void)
{
	ta_crypto_caps.nb_algo         = get_nb_algo();
	ta_crypto_caps.sizeof_alg_list = get_size_name_alg_list();
	return TEE_SUCCESS;
}

/* Called each time an instance is destroyed */
void TA_DestroyEntryPoint(void)
{
}

/* Called each time a session is opened */
TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes, TEE_Param pParams[4],
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

static TEE_Result TA_GetCaps(uint32_t ParamTypes, TEE_Param Params[4])
{
	uint32_t exp_ParamTypes = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	if (ParamTypes != exp_ParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	if (Params[0].memref.size < sizeof(struct ta_caps))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Fill the TA Crypto caps structure */
	memcpy(Params[0].memref.buffer, &ta_crypto_caps,
		sizeof(struct ta_caps));

	return TEE_SUCCESS;
}

static TEE_Result TA_GetListAlg(uint32_t ParamTypes, TEE_Param Params[4])
{
	uint32_t exp_ParamTypes = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	if (ParamTypes != exp_ParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	if ((Params[0].memref.size < get_size_name_alg_list()) ||
		(Params[0].memref.buffer == NULL))
		return TEE_ERROR_BAD_PARAMETERS;

	copy_name_alg_list(Params[0].memref.buffer);
	return TEE_SUCCESS;
}

static TEE_Result TA_PrepareAlgo(uint32_t ParamTypes, TEE_Param Params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t alg_id;
	uint32_t exp_ParamTypes = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_VALUE_OUTPUT,
		TEE_PARAM_TYPE_NONE);

	if (ParamTypes != exp_ParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	if (Params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	alg_id = get_alg_id(Params[0].memref.buffer, Params[0].memref.size);

	Params[2].value.a = alg_id;

	if (alg_id == (uint32_t)(-1))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Call Algorithm's class preparation function */
	switch (TEE_ALG_GET_CLASS(alg_id)) {
	case TEE_OPERATION_CIPHER:
		res = TA_CipherPrepareAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_DIGEST:
		res = TA_DigestPrepareAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_MAC:
		res = TA_MacPrepareAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_ASYMMETRIC_CIPHER:
		res = TA_AsymCipherPrepareAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_ASYMMETRIC_SIGNATURE:
		res = TA_AsymDigestPrepareAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_KEY_DERIVATION:
		res = TA_KeyDerivePrepareAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_AE:
		res = TA_AuthenEncPrepareAlgo(alg_id, Params);
		break;

	default:
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;
}

static TEE_Result TA_ProcessAlgo(uint32_t ParamTypes, TEE_Param Params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t alg_id;
	uint32_t exp_ParamTypes = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_NONE);

	if (ParamTypes != exp_ParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	if (Params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (Params[1].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (Params[2].value.a == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	alg_id = Params[2].value.a;

	/* Call Algorithm's class process function */
	switch (TEE_ALG_GET_CLASS(alg_id)) {
	case TEE_OPERATION_CIPHER:
		res = TA_CipherProcessAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_DIGEST:
		res = TA_DigestProcessAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_MAC:
		res = TA_MacProcessAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_ASYMMETRIC_CIPHER:
		res = TA_AsymCipherProcessAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_ASYMMETRIC_SIGNATURE:
		res = TA_AsymDigestProcessAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_KEY_DERIVATION:
		res = TA_KeyDeriveProcessAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_AE:
		res = TA_AuthenEncProcessAlgo(alg_id, Params);
		break;

	default:
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;
}

static TEE_Result TA_FreeAlgo(uint32_t ParamTypes, TEE_Param Params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t alg_id;
	uint32_t exp_ParamTypes = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_NONE);

	if (ParamTypes != exp_ParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	if (Params[0].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (Params[1].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (Params[2].value.a == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	alg_id = Params[2].value.a;

	/* Call Algorithm's free function */
	switch (TEE_ALG_GET_CLASS(alg_id)) {
	case TEE_OPERATION_CIPHER:
		res = TA_CipherFreeAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_DIGEST:
		res = TA_DigestFreeAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_MAC:
		res = TA_MacFreeAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_ASYMMETRIC_CIPHER:
		res = TA_AsymCipherFreeAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_ASYMMETRIC_SIGNATURE:
		res = TA_AsymDigestFreeAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_KEY_DERIVATION:
		res = TA_KeyDeriveFreeAlgo(alg_id, Params);
		break;

	case TEE_OPERATION_AE:
		res = TA_AuthenEncFreeAlgo(alg_id, Params);
		break;

	default:
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;

}

/* Called when a command is invoked */
TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
				      uint32_t nCommandID, uint32_t nParamTypes,
				      TEE_Param pParams[4])
{
	(void)pSessionContext;
	switch (nCommandID) {
	case TA_CRYPTO_PERF_CMD_GET_CAPS:
		/* Returns the TA Capabilities */
		return TA_GetCaps(nParamTypes, pParams);

	case TA_CRYPTO_PERF_CMD_GET_LIST_ALG:
		/* Copy the List of Algorithms' name */
		return TA_GetListAlg(nParamTypes, pParams);

	case TA_CRYPTO_PERF_CMD_PREPARE_ALG:
		/* Prepare the algorithm */
		return TA_PrepareAlgo(nParamTypes, pParams);

	case TA_CRYPTO_PERF_CMD_PROCESS:
		return TA_ProcessAlgo(nParamTypes, pParams);

	case TA_CRYPTO_PERF_CMD_FREE_ALG:
		return TA_FreeAlgo(nParamTypes, pParams);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
