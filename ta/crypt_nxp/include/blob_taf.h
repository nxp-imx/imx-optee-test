/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019, NXP
 */

#ifndef __BLOB_TAF_H__
#define __BLOB_TAF_H__

#include <pta_blob.h>

TEE_Result blob_test_param_encaps(uint32_t param_types, TEE_Param params[4]);
TEE_Result blob_test_param_decaps(uint32_t param_types, TEE_Param params[4]);
TEE_Result blob_tests(uint32_t param_types, TEE_Param params[4]);

#endif /* __BLOB_TAF_H__ */
