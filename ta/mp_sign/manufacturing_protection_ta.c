// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 */

#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <pta_imx_manufacturing_protection.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <ta_manufacturing_protection.h>

/*
 * Define a type buffer to handle data and length
 */
struct ptabuf {
	uint8_t *data;
	size_t length;
};

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types __unused,
				    TEE_Param params[4] __unused,
				    void **sess_ctx __unused)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx __unused)
{
}

/*
 * Write the public key in PEM format
 *
 * Returns TEE_SUCCESS or error code
 */
static TEE_Result ta_write_pubkey_pem(const struct ptabuf *pubkey,
				      struct ptabuf *pubkey_pem)
{
	int ret = MBEDTLS_ERR_PK_ALLOC_FAILED;
	mbedtls_ecp_keypair *ecdsa_keypair = NULL;
	mbedtls_pk_context ctx = {};

	mbedtls_pk_init(&ctx);

	/* Initialize the context and set the keypair */
	ret = mbedtls_pk_setup(&ctx,
			       mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	if (ret != 0) {
		EMSG("mbedtls_pk_setup: failed: 0x%" PRIx32, ret);
		goto out;
	}

	ecdsa_keypair = ctx.private_pk_ctx;

	/* generate the ecdsa context with the P256 curve */
	ret = mbedtls_ecp_group_load(&ecdsa_keypair->private_grp,
				     MBEDTLS_ECP_DP_SECP256R1);
	if (ret != 0) {
		EMSG("mbedtls_ecp_group_load (group): failed: 0x%" PRIx32, ret);
		goto out;
	}

	/* set the ECP point from public key buffer */
	ret = mbedtls_ecp_point_read_binary(&ecdsa_keypair->private_grp,
					    &ecdsa_keypair->private_Q,
					    pubkey->data, pubkey->length);
	if (ret != 0) {
		EMSG("mbedtls_ecp_point_write_binary : failed: 0x%" PRIx32,
		     ret);
		goto out;
	}

	/* Write the public key to a PEM string buffer */
	ret = mbedtls_pk_write_pubkey_pem(&ctx, pubkey_pem->data,
					  pubkey_pem->length);
	if (ret != 0) {
		EMSG("mbedtls_pk_write_pubkey_pem : failed: 0x%" PRIx32, ret);
		goto out;
	}

out:
	mbedtls_pk_free(&ctx);

	return ret ? TEE_ERROR_GENERIC : TEE_SUCCESS;
}

static TEE_Result sign_message(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct ptabuf message = {};
	struct ptabuf signature = {};
	struct ptabuf mpmr = {};
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);
	TEE_TASessionHandle session = TEE_HANDLE_NULL;
	TEE_UUID uuid = PTA_MANUFACT_PROTEC_UUID;
	uint32_t err_origin = 0;
	uint32_t sign_param_types = 0;
	TEE_Param sign_params[4] = {};

	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	message.data = params[0].memref.buffer;
	message.length = params[0].memref.size;

	signature.data = params[1].memref.buffer;
	signature.length = params[1].memref.size;

	mpmr.data = params[2].memref.buffer;
	mpmr.length = params[2].memref.size;

	/* Open session to PTA */
	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &session, &err_origin);
	if (res != TEE_SUCCESS) {
		EMSG("TEE open session failed with code 0x%" PRIx32
		     " origin 0x%" PRIx32,
		     res, err_origin);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Call PTA to sign message */
	sign_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE);
	sign_params[0].memref.buffer = message.data;
	sign_params[0].memref.size = message.length;

	sign_params[1].memref.buffer = signature.data;
	sign_params[1].memref.size = signature.length;

	sign_params[2].memref.buffer = mpmr.data;
	sign_params[2].memref.size = mpmr.length;

	res = TEE_InvokeTACommand(session, 0, PTA_IMX_MP_CMD_SIGNATURE_MPMR,
				  sign_param_types, sign_params, &err_origin);
	signature.length = sign_params[1].memref.size;
	mpmr.length = sign_params[2].memref.size;

	if (res != TEE_SUCCESS) {
		EMSG("%s failed with code 0x%" PRIx32,
		     "PTA_IMX_MP_CMD_SIGNATURE_MPMR", res);
		goto out;
	}

out:
	/* Update output lengths */
	params[1].memref.size = signature.length;
	params[2].memref.size = mpmr.length;

	TEE_CloseTASession(session);
	return res;
}

static TEE_Result get_mp_pubk(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct ptabuf mp_pubkey = {};
	struct ptabuf pubkey_raw_pem = {};
	struct ptabuf mp_pubkey_pem = {};
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	TEE_TASessionHandle session = TEE_HANDLE_NULL;
	TEE_UUID uuid = PTA_MANUFACT_PROTEC_UUID;
	uint32_t err_origin = 0;
	uint32_t getmppubk_param_types = 0;
	TEE_Param getmppubk_params[4] = {};

	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	mp_pubkey.data = params[0].memref.buffer;
	mp_pubkey.length = params[0].memref.size;

	mp_pubkey_pem.data = params[1].memref.buffer;
	mp_pubkey_pem.length = params[1].memref.size;

	/* Open session to PTA */
	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &session, &err_origin);
	if (res != TEE_SUCCESS) {
		EMSG("TEE open session failed with code 0x%" PRIx32
		     " origin 0x%" PRIx32,
		     res, err_origin);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Call PTA to retrieve MP public key */
	getmppubk_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	getmppubk_params[0].memref.buffer = mp_pubkey.data;
	getmppubk_params[0].memref.size = mp_pubkey.length;

	res = TEE_InvokeTACommand(session, 0, PTA_IMX_MP_CMD_GET_PUBLIC_KEY,
				  getmppubk_param_types, getmppubk_params,
				  &err_origin);
	mp_pubkey.length = getmppubk_params[0].memref.size;

	if (res != TEE_SUCCESS) {
		EMSG("%s failed with code 0x%" PRIx32,
		     "PTA_IMX_MP_CMD_GET_PUBLIC_KEY", res);
		goto out;
	}

	/*
	 * Transform the hex representation of the public key into raw PEM
	 * This can be done by prepending the byte 0x04 before the public key
	 *
	 * We allocate a temporary buffer to pass to mbedtls adding the
	 * necessary leading byte
	 */
	pubkey_raw_pem.length = mp_pubkey.length + 1;
	pubkey_raw_pem.data = TEE_Malloc(pubkey_raw_pem.length, 0);
	if (!pubkey_raw_pem.data) {
		EMSG("Failed allocate mem for RAW PEM");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* RAW PEM */
	pubkey_raw_pem.data[0] = 0x4;
	memcpy(&pubkey_raw_pem.data[1], mp_pubkey.data, mp_pubkey.length);

	res = ta_write_pubkey_pem(&pubkey_raw_pem, &mp_pubkey_pem);
	if (res != TEE_SUCCESS) {
		EMSG("ta_write_cert failed with code 0x%" PRIx32, res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

out:
	/* Update output lengths */
	params[0].memref.size = mp_pubkey.length;
	params[1].memref.size = mp_pubkey_pem.length;

	TEE_Free(pubkey_raw_pem.data);
	TEE_CloseTASession(session);
	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __unused, uint32_t cmd_id,
				      uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_MP_CMD_SIGN_DATA:
		return sign_message(param_types, params);
	case TA_MP_CMD_GET_MP_PUBK:
		return get_mp_pubk(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
