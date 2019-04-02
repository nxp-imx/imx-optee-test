/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019, NXP
 */

#ifndef __USER_TA_HEADER_DEFINES_H__
#define __USER_TA_HEADER_DEFINES_H__

#include <ta_crypt_nxp.h>

#define TA_UUID TA_CRYPT_NXP_UUID

#define TA_FLAGS		(TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE		(32 * 1024)
#define TA_DATA_SIZE		(32 * 1024)

#endif /* __USER_TA_HEADER_DEFINES_H__ */
