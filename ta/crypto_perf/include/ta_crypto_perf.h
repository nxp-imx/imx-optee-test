/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2021 NXP
 */

#ifndef __TA_CRYPTO_PERF_H__
#define __TA_CRYPTO_PERF_H__

#include <ta_crypto_perf_test.h>
#include <tee_api.h>
#include <utee_defines.h>

#define FORCE_DEBUG 0

#ifndef FORCE_DEBUG
#define CHECK(res, name, action) do { \
		if ((res) != TEE_SUCCESS) { \
			DMSG(name ": 0x%08x", (res)); \
			action \
		} \
	} while (0)
#else
#define CHECK(res, name, action) do { \
		if ((res) != TEE_SUCCESS) { \
			MSG(name ": 0x%08x", (res)); \
			action \
		} \
	} while (0)
#endif

uint32_t get_nb_algo(void);
uint32_t get_size_name_alg_list(void);
void     copy_name_alg_list(char *buffer);
uint32_t get_alg_id(char *name, size_t size);


/* Cipher Functions */
TEE_Result TA_CipherPrepareAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_CipherProcessAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_CipherFreeAlgo(uint32_t algo, TEE_Param params[4]);

/* Digest Functions */
TEE_Result TA_DigestPrepareAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_DigestProcessAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_DigestFreeAlgo(uint32_t algo, TEE_Param params[4]);

/* Mac Functions */
TEE_Result TA_MacPrepareAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_MacProcessAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_MacFreeAlgo(uint32_t algo, TEE_Param params[4]);

/* Asymmetric Cipher Functions */
TEE_Result TA_AsymCipherPrepareAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_AsymCipherProcessAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_AsymCipherFreeAlgo(uint32_t algo, TEE_Param params[4]);

/* Asymmetric Digest Functions */
TEE_Result TA_AsymDigestPrepareAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_AsymDigestProcessAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_AsymDigestFreeAlgo(uint32_t algo, TEE_Param params[4]);

/* Key Derivation Functions */
TEE_Result TA_KeyDerivePrepareAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_KeyDeriveProcessAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_KeyDeriveFreeAlgo(uint32_t algo, TEE_Param params[4]);

/* Authenticated Encryption Functions */
TEE_Result TA_AuthenEncPrepareAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_AuthenEncProcessAlgo(uint32_t algo, TEE_Param params[4]);
TEE_Result TA_AuthenEncFreeAlgo(uint32_t algo, TEE_Param params[4]);
#endif
