// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018 NXP
 */

#include <stdio.h>
#include <trace.h>

#include <tee_ta_api.h>
#include <user_ta_header_defines.h>
#include <ta_crypto_perf.h>

static TEE_OperationHandle digest_op;

static void TA_FreeOp(void)
{
	if (digest_op) {
		TEE_FreeOperation(digest_op);
		digest_op = NULL;
	}
}


TEE_Result TA_DigestPrepareAlgo(uint32_t algo, TEE_Param params[4] __unused)
{
	/* Digest Preparation: Don't need to check again input params */
	TEE_Result res;

	/*
	 * Just in case there was an issue and Operation Handle
	 * was no freed
	 */
	TA_FreeOp();

	res = TEE_AllocateOperation(&digest_op, algo, TEE_MODE_DIGEST, 0);
	CHECK(res, "TEE_AllocateOperation Digest", goto PrepareExit_Error;);

	return TEE_SUCCESS;

PrepareExit_Error:
	TA_FreeOp();
	return res;
}

TEE_Result TA_DigestProcessAlgo(uint32_t algo __unused, TEE_Param params[4])
{
	/* Digest Process: Don't need to check again input params */
	TEE_Result res;
	void *in, *out;
	uint32_t inSize;
	uint32_t outSize;

	in      = params[0].memref.buffer;
	inSize  = params[0].memref.size;
	out     = params[1].memref.buffer;
	outSize = params[1].memref.size;

	res = TEE_DigestDoFinal(digest_op, in, inSize, out, &outSize);
	CHECK(res, "TEE_DigestDoFinal Digest", return res;);

	return TEE_SUCCESS;

}

TEE_Result TA_DigestFreeAlgo(uint32_t algo __unused,
	TEE_Param params[4] __unused)
{
	/* Digest Free: Don't need to check again input params */
	TA_FreeOp();
	return TEE_SUCCESS;
}
