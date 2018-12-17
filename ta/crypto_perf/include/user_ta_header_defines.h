/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018 NXP
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ta_crypto_perf.h>

#define TA_UUID TA_CRYPTO_PERF_TEST_UUID

#define TA_FLAGS		(TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR | \
				TA_FLAG_SINGLE_INSTANCE)
#define TA_STACK_SIZE		(4 * 1024)
#define TA_DATA_SIZE		(64 * 1024)

#endif /* USER_TA_HEADER_DEFINES_H */
