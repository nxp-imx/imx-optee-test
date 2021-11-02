/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef TA_MANUFACTURING_PROTECTION_H
#define TA_MANUFACTURING_PROTECTION_H

/*  TA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html */
#define TA_MANUFACTURING_PROTECTION_UUID \
	{ \
		0x8aaaf200, 0x2450, 0x11e4, \
		{ \
			0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1c \
		} \
	}

/* PTA ID implemented in the TA */
#define TA_MP_CMD_SIGN_DATA   0
#define TA_MP_CMD_GET_MP_PUBK 1

/*
 * MP Public key maximum size in bytes
 * Maximum is 2*66 bytes for the ECDSA P521
 * Add 1 bytes for the key format
 */
#define MP_PUBKEY_SIZE_NAX ((2 * 66) + 1)

/*
 * Calculate the Maximum size of the MP Public Key size in PEM
 *         format.
 * -----BEGIN PUBLIC KEY-----\n
 * [MP Key in PEM]
 * -----END PUBLIC KEY-----\n
 */
#define MP_PUBKEY_PEM_SIZE_MAX \
	(sizeof("-----BEGIN PUBLIC KEY-----\n") + \
	 ((((MP_PUBKEY_SIZE_NAX / 3) + 1) * 4) + 1) + \
	 sizeof("-----END PUBLIC KEY-----\n"))

#endif /* TA_MANUFACTURING_PROTECTION_H */
