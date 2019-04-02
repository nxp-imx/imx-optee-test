/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019, NXP
 */

#ifndef __TA_CRYPT_NXP_H__
#define __TA_CRYPT_NXP_H__

/* This UUID is generated with the ITU-T UUID generator at
   http://www.itu.int/ITU-T/asn1/uuid.html */
#define TA_CRYPT_NXP_UUID { 0x6e212e72, 0xcc01, 0x4ead, \
	{ 0x8c, 0x9b, 0x64, 0xbf, 0xce, 0xb9, 0x9a, 0x1a } }

/*
 * in	params[0].value.a = Blob Type (enum PTA_BLOB_TYPE)
 * in	params[1].memref = Input plaintext data to encapsulate
 * out	params[2].memref = Output plaintext data decapsulated
 */
#define TA_CRYPT_CMD_BLOB_TESTS 46

/*
 * in	params[0].value.a = Blob Type (enum PTA_BLOB_TYPE)
 * in	params[1].memref = Input plaintext data to encapsulate
 * out	params[2].memref = Output plaintext data decapsulated
 */
#define TA_CRYPT_CMD_BLOB_TEST_PARAM_ENCAPS 47

/*
 * in	params[0].value.a = Blob Type (enum PTA_BLOB_TYPE)
 * in	params[1].memref = Input plaintext data to encapsulate
 * out	params[2].memref = Output plaintext data decapsulated
 */
#define TA_CRYPT_CMD_BLOB_TEST_PARAM_DECAPS 48

#endif /* __TA_CRYPT_NXP_H_ */
