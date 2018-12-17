/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018 NXP
 */

#ifndef __TA_CRYPTO_PERF_TEST_H__
#define __TA_CRYPTO_PERF_TEST_H__

#include <tee_api_types.h>

/* This UUID is generated with uuidgen */
#define TA_CRYPTO_PERF_TEST_UUID { 0x690d2100, 0xdbe5, 0x11e6, \
	{ 0xbf, 0x26, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01 } }

/* TA Capabilities structure */
struct ta_caps {
	uint8_t  nb_algo;
	uint32_t sizeof_alg_list;

};

/* Define of TA Command available */
#define TA_CRYPTO_PERF_CMD_GET_CAPS		(1)
#define TA_CRYPTO_PERF_CMD_GET_LIST_ALG	(2)
#define TA_CRYPTO_PERF_CMD_PREPARE_ALG	(3)
#define TA_CRYPTO_PERF_CMD_PROCESS		(4)
#define TA_CRYPTO_PERF_CMD_FREE_ALG		(5)

#endif
