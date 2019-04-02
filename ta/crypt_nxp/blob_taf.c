// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019, NXP
 */

/* Global Includes */
#include <tee_internal_api.h>

/* Local Includes */
#include "blob_taf.h"

TEE_Result blob_test_param_encaps(uint32_t param_types, TEE_Param params[4])
{
	static const TEE_UUID pta_blob_uuid = PTA_BLOB_PTA_UUID;
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Result res;
	uint32_t ret_orig;

	uint8_t *blob_buf = NULL;
	size_t  blob_size;

	uint8_t key[PTA_BLOB_KEY_SIZE] = {0};
	uint32_t pta_param_types;
	TEE_Param pta_params[4] = {0};

	if (param_types != TEE_PARAM_TYPES(
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_GenerateRandom(key, sizeof(key));

	/*
	 * Allocate the blob buffer
	 * Size of the blob is corresponding to the data size +
	 * a padding (blob recovery key + blob MAC)
	 */
	blob_size = params[1].memref.size + PTA_BLOB_PAD_SIZE;
	blob_buf = TEE_Malloc(blob_size, 0);
	if (!blob_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_OpenTASession(&pta_blob_uuid, 0, 0, NULL, &sess, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_OpenTASession failed");
		goto exit_test;
	}

	/*
	 * First prepare the operation to encapsulate input data in
	 * the asked blob type
	 */
	pta_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT);

	/*
	 * Prepare the PTA parameters to encapsulate the payload
	 */
	// Blob Type
	pta_params[0].value.a = params[0].value.a;
	// Key derivation
	pta_params[1].memref.buffer = key;
	pta_params[1].memref.size   = sizeof(key);
	// Input Plain text data to encapsulate
	pta_params[2].memref.buffer = params[1].memref.buffer;
	pta_params[2].memref.size   = params[1].memref.size;
	// Blob result
	pta_params[3].memref.buffer = blob_buf;
	pta_params[3].memref.size   = blob_size;

	/*
	 * Test the parameters limits
	 */
	// Bad Blob Type
	pta_params[0].value.a = params[0].value.a + 10;
	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_ENCAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res != TEE_ERROR_BAD_PARAMETERS) {
		EMSG("Blob Encaps with Bad Type failed");
		goto exit_test;
	}
	// Restore Blob Type
	pta_params[0].value.a = params[0].value.a;

	// Bad Key derivation size
	pta_params[1].memref.size = 0;
	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_ENCAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res != TEE_ERROR_BAD_PARAMETERS) {
		EMSG("Blob Encaps with Bad Key Derivation Size failed");
		goto exit_test;
	}

	// Restore Key Derivation size
	pta_params[1].memref.size = sizeof(key);

	// Bad Blob Size
	pta_params[3].memref.size = blob_size - 1;
	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_ENCAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res != TEE_ERROR_SHORT_BUFFER) {
		EMSG("Blob Encaps with Bad Blob Size failed");
		goto exit_test;
	}

	// Restore Blob size
	pta_params[3].memref.size = blob_size;

	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_ENCAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeTACommand failed");
		goto exit_test;
	}

	blob_size = pta_params[3].memref.size;

	/*
	 * Prepare the PTA parameters to decapsulate the payload
	 * Same blob type, same key derivation
	 */
	// Input Blob to decapsulate
	pta_params[2].memref.buffer = blob_buf;
	pta_params[2].memref.size   = blob_size;
	// Plaintext resulting
	pta_params[3].memref.buffer = params[2].memref.buffer;
	pta_params[3].memref.size   = params[2].memref.size;

	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_DECAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeTACommand failed");
		goto exit_test;
	}

	/* Set the size of the decapsulated data */
	params[2].memref.size = pta_params[3].memref.size;

exit_test:
	if (blob_buf)
		TEE_Free(blob_buf);

	TEE_CloseTASession(sess);
	return res;
}

TEE_Result blob_test_param_decaps(uint32_t param_types, TEE_Param params[4])
{
	static const TEE_UUID pta_blob_uuid = PTA_BLOB_PTA_UUID;
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Result res;
	uint32_t ret_orig;

	uint8_t *blob_buf = NULL;
	size_t  blob_size;

	uint8_t key[PTA_BLOB_KEY_SIZE] = {0};
	uint32_t pta_param_types;
	TEE_Param pta_params[4] = {0};

	if (param_types != TEE_PARAM_TYPES(
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_GenerateRandom(key, sizeof(key));

	/*
	 * Allocate the blob buffer
	 * Size of the blob is corresponding to the data size +
	 * a padding (blob recovery key + blob MAC)
	 */
	blob_size = params[1].memref.size + PTA_BLOB_PAD_SIZE;
	blob_buf = TEE_Malloc(blob_size, 0);
	if (!blob_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_OpenTASession(&pta_blob_uuid, 0, 0, NULL, &sess, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_OpenTASession failed");
		goto exit_test;
	}

	/*
	 * First prepare the operation to encapsulate input data in
	 * the asked blob type
	 */
	pta_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT);

	/*
	 * Prepare the PTA parameters to encapsulate the payload
	 */
	// Blob Type
	pta_params[0].value.a = params[0].value.a;
	// Key derivation
	pta_params[1].memref.buffer = key;
	pta_params[1].memref.size   = sizeof(key);
	// Input Plain text data to encapsulate
	pta_params[2].memref.buffer = params[1].memref.buffer;
	pta_params[2].memref.size   = params[1].memref.size;
	// Blob result
	pta_params[3].memref.buffer = blob_buf;
	pta_params[3].memref.size   = blob_size;

	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_ENCAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeTACommand failed");
		goto exit_test;
	}

	blob_size = pta_params[3].memref.size;

	/*
	 * Prepare the PTA parameters to decapsulate the payload
	 * Same blob type, same key derivation
	 */
	// Input Blob to decapsulate
	pta_params[2].memref.buffer = blob_buf;
	pta_params[2].memref.size   = blob_size;
	// Plaintext resulting
	pta_params[3].memref.buffer = params[2].memref.buffer;
	pta_params[3].memref.size   = params[2].memref.size;

	/*
	 * Test the parameters limits
	 */
	// Bad Blob Type
	pta_params[0].value.a = params[0].value.a + 10;
	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_DECAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res != TEE_ERROR_BAD_PARAMETERS) {
		EMSG("Blob Decaps with Bad Type failed");
		goto exit_test;
	}
	// Restore Blob Type
	pta_params[0].value.a = params[0].value.a;

	// Bad Key derivation size
	pta_params[1].memref.size = 0;
	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_DECAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res != TEE_ERROR_BAD_PARAMETERS) {
		EMSG("Blob Decaps with Bad Key Derivation Size failed");
		goto exit_test;
	}

	// Restore Key Derivation size
	pta_params[1].memref.size = sizeof(key);

	// Bad Blob Size
	pta_params[2].memref.size = blob_size + 1;
	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_DECAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res != TEE_ERROR_SHORT_BUFFER) {
		EMSG("Blob Decaps with Bad Blob Size failed");
		goto exit_test;
	}

	// Restore Blob size
	pta_params[2].memref.size = blob_size;

	// Bad Data Size
	pta_params[3].memref.size = params[2].memref.size - 1;
	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_DECAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res != TEE_ERROR_SHORT_BUFFER) {
		EMSG("Blob Decaps with Bad Blob Size failed");
		goto exit_test;
	}

	// Restore Data size
	pta_params[3].memref.size = params[2].memref.size;

	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_DECAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeTACommand failed");
		goto exit_test;
	}

	/* Set the size of the decapsulated data */
	params[2].memref.size = pta_params[3].memref.size;

exit_test:
	if (blob_buf)
		TEE_Free(blob_buf);

	TEE_CloseTASession(sess);
	return res;
}
TEE_Result blob_tests(uint32_t param_types, TEE_Param params[4])
{
	static const TEE_UUID pta_blob_uuid = PTA_BLOB_PTA_UUID;
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Result res;
	uint32_t ret_orig;

	uint8_t *blob_buf = NULL;
	size_t  blob_size;

	uint8_t key[PTA_BLOB_KEY_SIZE] = {0};
	uint32_t pta_param_types;
	TEE_Param pta_params[4] = {0};

	if (param_types != TEE_PARAM_TYPES(
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_GenerateRandom(key, sizeof(key));

	/*
	 * Allocate the blob buffer
	 * Size of the blob is corresponding to the data size +
	 * a padding (blob recovery key + blob MAC)
	 */
	blob_size = params[1].memref.size + PTA_BLOB_PAD_SIZE;
	blob_buf = TEE_Malloc(blob_size, 0);
	if (!blob_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_OpenTASession(&pta_blob_uuid, 0, 0, NULL, &sess, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_OpenTASession failed");
		goto exit_test;
	}

	/*
	 * First prepare the operation to encapsulate input data in
	 * the asked blob type
	 */
	pta_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_VALUE_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT);

	/*
	 * Prepare the PTA parameters to encapsulate the payload
	 */
	// Blob Type
	pta_params[0].value.a = params[0].value.a;
	// Key derivation
	pta_params[1].memref.buffer = key;
	pta_params[1].memref.size   = sizeof(key);
	// Input Plain text data to encapsulate
	pta_params[2].memref.buffer = params[1].memref.buffer;
	pta_params[2].memref.size   = params[1].memref.size;
	// Blob result
	pta_params[3].memref.buffer = blob_buf;
	pta_params[3].memref.size   = blob_size;

	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_ENCAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res == TEE_SUCCESS) {
		EMSG("Blob Encaps with Bad Blob Size failed");
		goto exit_test;
	}

	// Restore Blob size
	pta_params[3].memref.size = blob_size;

	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_ENCAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeTACommand failed");
		goto exit_test;
	}

	blob_size = pta_params[3].memref.size;

	/*
	 * Prepare the PTA parameters to decapsulate the payload
	 * Same blob type, same key derivation
	 */
	// Input Blob to decapsulate
	pta_params[2].memref.buffer = blob_buf;
	pta_params[2].memref.size   = blob_size;
	// Plaintext resulting
	pta_params[3].memref.buffer = params[2].memref.buffer;
	pta_params[3].memref.size   = params[2].memref.size;

	res = TEE_InvokeTACommand(sess, 0, PTA_BLOB_CMD_DECAPS,
				  pta_param_types, pta_params, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeTACommand failed");
		goto exit_test;
	}

	/* Set the size of the decapsulated data */
	params[2].memref.size = pta_params[3].memref.size;

exit_test:
	if (blob_buf)
		TEE_Free(blob_buf);

	TEE_CloseTASession(sess);
	return res;
}
