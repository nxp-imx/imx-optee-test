// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <util.h>
#include <unistd.h>

#include <tee_client_api.h>
#include <utee_defines.h>

#include "crypto_common.h"
#include "ta_crypto_perf_test.h"

/*
 * Default values
 */
#define DEFAULT_KEY_SIZE	128
#define DEFAULT_LOOP		1000
#define DEFAULT_BUFFER_SIZE	1024

#define ERROR_BAD_TEST_MASK		(-1100)
#define ERROR_BAD_TEST_GENERIC	(ERROR_BAD_TEST_MASK | 1)
#define ERROR_BAD_TEST_SC_INPUT (ERROR_BAD_TEST_MASK | 2)
#define ERROR_BAD_TEST_C_INPUT  (ERROR_BAD_TEST_MASK | 3)
#define ERROR_BAD_TEST_DIGEST   (ERROR_BAD_TEST_MASK | 4)

#define ERROR_GET_CAPS			(-1001)
#define ERROR_OPEN_TA_CTX		(-1002)
#define ERROR_OPEN_TA_SESSION	(-1003)
#define ERROR_ALLOCATE_SHM		(-1004)
#define ERROR_READ_RANDOM_FILE	(-1005)
#define ERROR_TA_PREP_ALGO		(-1006)
#define ERROR_TA_CMD_PROCESS	(-1007)
#define ERROR_TA_FREE_ALGO		(-1008)

//#define COLLECT_DATA
#ifdef COLLECT_DATA
static FILE * dataFile;
#define PRINT_DATA(idx, t)	fprintf(dataFile, "%d:%llu\n", idx, t)
#define OPEN_DATA(name)		(dataFile = fopen(name, "a"))
#define CLOSE_DATA do { \
		fflush(dataFile); \
		fsync(fileno(dataFile)); \
		fclose(dataFile); \
	} while (0)

#else
#define PRINT_DATA(idx, t)
#define OPEN_DATA(name)
#define CLOSE_DATA
#endif

/* Local function prototypes */
static int free_algo(TEEC_Operation *op);

/*
 * Hash Algo Names
 */
static const char * const hash_name[] = {
	NULL, "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"};
/*
 * TEE client stuff
 */

static TEEC_Context ctx  = { 0 };
static TEEC_Session sess = { 0 };

static const char * const str_sizes[] = { "MB", "KB", "B" };
static const uint32_t KB = 1024;
static const uint32_t MB = 1024 * 1024;
static char           HeadP1Empty[100];

/*
 * Local Data
 */
static struct ta_caps ta_caps;
static char *name_alg_list;

struct test_param {
	char     alg[40];
	uint8_t  verbose;
	uint8_t	 in_place;
	uint8_t	 in_random;
	uint16_t keysize;
	uint32_t loop;
	uint32_t bufsize;
};

static void setdefault_param(struct test_param *test)
{
	memset(test->alg, 0, sizeof(test->alg));
	test->verbose   = 0;
	test->in_place  = 0;
	test->in_random = 0;
	test->keysize   = DEFAULT_KEY_SIZE;
	test->loop      = DEFAULT_LOOP;
	test->bufsize   = DEFAULT_BUFFER_SIZE;
}

/*
 * Statistics
 *
 * We want to compute min, max, mean and standard deviation of processing time
 */

struct statistics {
	int n;
	double m;
	double M2;
	double min;
	double max;
	int initialized;
	size_t data_size;
};

/* Take new sample into account (Knuth/Welford algorithm) */
static void update_stats(struct statistics *s, uint64_t t)
{
	double x = (double)t;
	double delta = x - s->m;

	s->n++;
	s->m += delta/s->n;
	s->M2 += delta*(x - s->m);
	if (!s->initialized) {
		s->min = s->max = x;
		s->initialized = 1;
	} else {
		if (s->min > x)
			s->min = x;
		if (s->max < x)
			s->max = x;
	}

	PRINT_DATA(s->n, t);
}

static void get_current_time(struct timespec *ts)
{
	if (clock_gettime(CLOCK_MONOTONIC, ts) < 0) {
		perror("clock_gettime");
		exit(1);
	}
}

static uint64_t timespec_to_ns(struct timespec *ts)
{
	return ((uint64_t)ts->tv_sec * 1000000000) + ts->tv_nsec;
}

static uint64_t timespec_diff_ns(struct timespec *start, struct timespec *end)
{
	return timespec_to_ns(end) - timespec_to_ns(start);
}

static double stddev(struct statistics *s)
{
	if (s->n < 2)
		return NAN;
	return sqrt(s->M2 / s->n);
}

static double mb_per_sec(size_t size, double usec)
{
	return (1000000 / usec) * ((double)size / MB);
}

static int check_res(TEEC_Result res, const char *errmsg)
{
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "%s: 0x%08x\n", errmsg, res);
		return (-1);
	}
	return 0;
}

/* Print Log file */
static char *size_to_str(uint32_t size, char *str)
{
	uint8_t  idx;
	uint32_t mul = MB;

	for (idx = 0; idx < ARRAY_SIZE(str_sizes); idx++, mul /= KB) {
		if (size < mul)
			continue;

		if ((size % mul) == 0)
			sprintf(str, "%d %s", (size / mul), str_sizes[idx]);
		else
			sprintf(str, "%.1f %s", ((float)size / mul),
				str_sizes[idx]);
		return str;
	}

	sprintf(str, "0 B");
	return str;
}

static uint32_t strsize_to_bytes(char *str)
{
	float size = atof(str);
	char     unit;

	/* Check unit if specified */
	unit = str[strlen(str) - 1];

	switch (unit) {
	case 'b':
	case 'B':
		/* Bytes */
		break;

	case 'K':
	case 'k':
		/* KBytes */
		size *= KB;
		break;

	case 'M':
	case 'm':
		/* MBytes */
		size *= MB;
		break;

	default:
		break;
	}

	if ((uint32_t)size == 0)
		return (uint32_t)(-1);

	return size;
}

static void print_log_header(FILE *log)
{
	char HeadPart1[100];

	if (log == NULL)
		return;

	sprintf(HeadPart1,  " %-28s | Key | Loop | Rand | I=O ",
			"Algorithm Name");
	sprintf(HeadP1Empty, "%28c |     |      |      |     ", ' ');
	fprintf(log, "%s", HeadPart1);
	fprintf(log, "| Op  |   Size   |  min (μs)  |  max (μs)  |");
	fprintf(log, "  mean (μs) | stddev(μs) |  MiB/s\n");

}

static void print_log_test(FILE *log, struct test_param *test)
{
	if (log == NULL)
		return;

	fprintf(log, "%-29s |", test->alg);
	fprintf(log, "%4d |%5d |", test->keysize, test->loop);

	if (test->in_random)
		fprintf(log, "%5s |", "Yes");
	else
		fprintf(log, "%5s |", "No");

	if (test->in_place)
		fprintf(log, "%4s |", "Yes");
	else
		fprintf(log, "%4s |", "No");
}

static void print_log_result(FILE *log, uint8_t reverse,
					 struct statistics *stats_enc,
					 struct statistics *stats_dec,
					 double t_prep)
{
	char tmp[20];

	if (log == NULL)
		return;

	fprintf(log, " Pre |");
	fprintf(log, "%9c | ", ' ');
	fprintf(log, "%10g\n", t_prep);

	fprintf(log, " %s| Enc |", HeadP1Empty);
	fprintf(log, "%9s | ", size_to_str(stats_enc->data_size, tmp));
	fprintf(log, "%10g | %10g | %10g | %10g | %10g\n",
		(stats_enc->min / 1000),
		(stats_enc->max / 1000),
		(stats_enc->m / 1000),
		(stddev(stats_enc) / 1000),
		mb_per_sec(stats_enc->data_size, stats_enc->m / 1000));

	if (reverse) {
		fprintf(log, " %s| Dec |", HeadP1Empty);
		fprintf(log, "%9s | ", size_to_str(stats_dec->data_size, tmp));
		fprintf(log, "%10g | %10g | %10g | %10g | %10g\n",
		(stats_dec->min / 1000),
		(stats_dec->max / 1000),
		(stats_dec->m / 1000),
		(stddev(stats_dec) / 1000),
		mb_per_sec(stats_dec->data_size, stats_dec->m / 1000));

	}
}


/* TA Open/close */
static int open_ta(void)
{
	TEEC_Result res;
	TEEC_UUID uuid = TA_CRYPTO_PERF_TEST_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (check_res(res, "TEEC_InitializeContext") != 0)
		return ERROR_OPEN_TA_CTX;

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	if (check_res(res, "TEEC_OpenSession") != 0)
		return ERROR_OPEN_TA_SESSION;

	return 0;
}

static void close_ta(int ret)
{
	if (ret == ERROR_BAD_TEST_GENERIC)
		return;

	free(name_alg_list);

	if (ret != ERROR_OPEN_TA_SESSION)
		TEEC_CloseSession(&sess);

	if (ret != ERROR_OPEN_TA_CTX)
		TEEC_FinalizeContext(&ctx);
}

static ssize_t read_random(void *in, size_t size)
{
	FILE *rndfile = NULL;
	size_t readsize;

	rndfile = fopen("/dev/urandom", "r");
	if (!rndfile) {
		fprintf(stderr, "Open file [/dev/urandom] error\n");
		return 1;
	}

	readsize = fread(in, size, 1, rndfile);
	if (readsize != 1) {
		fprintf(stderr, "Can't read file [/dev/urandom]\n");
		return 1;
	}

	fclose(rndfile);

	return 0;
}

/* TA Get Caps */
static int getcaps_ta(void)
{
	uint32_t       ret_origin;
	TEEC_Result    res;
	TEEC_Operation op = {0};

	/* Check if Algorithms name already read */
	if (name_alg_list)
		return 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = &ta_caps;
	op.params[0].tmpref.size   = sizeof(struct ta_caps);

	res = TEEC_InvokeCommand(&sess, TA_CRYPTO_PERF_CMD_GET_CAPS,
			&op, &ret_origin);

	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "Get TA capabilities failed (0x%X)\n", res);
		return ERROR_GET_CAPS;
	}

	/* Allocate Memories to store the name of the algorithm */
	name_alg_list = malloc(ta_caps.sizeof_alg_list);

	if (!name_alg_list) {
		fprintf(stderr, "Can't allocate memory for algorithms name\n");
		return ERROR_GET_CAPS;
	}

	/* Get the name list from TA */
	op.params[0].tmpref.buffer = name_alg_list;
	op.params[0].tmpref.size   = ta_caps.sizeof_alg_list;

	res = TEEC_InvokeCommand(&sess, TA_CRYPTO_PERF_CMD_GET_LIST_ALG,
			&op, &ret_origin);

	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "Get TA Algorithms name failed (0x%X)\n", res);
		return ERROR_GET_CAPS;
	}

	return 0;
}

static void uppercase(char *out, char *in)
{
	do {
		*out = toupper(*in);
		in++;
		out++;
	} while (*in != '\0');
}

static size_t hash_size(uint8_t algo)
{
	switch (algo) {
	case TEE_MAIN_ALGO_MD5:
		return TEE_MD5_HASH_SIZE;

	case TEE_MAIN_ALGO_SHA1:
		return TEE_SHA1_HASH_SIZE;

	case TEE_MAIN_ALGO_SHA224:
		return TEE_SHA224_HASH_SIZE;

	case TEE_MAIN_ALGO_SHA256:
		return TEE_SHA256_HASH_SIZE;

	case TEE_MAIN_ALGO_SHA384:
		return TEE_SHA384_HASH_SIZE;

	case TEE_MAIN_ALGO_SHA512:
		return TEE_SHA512_HASH_SIZE;

	default:
		return 0;
	}
}

static int cipher_size(uint32_t algo, uint32_t size)
{
	if (size < TEE_AES_BLOCK_SIZE)
		return ERROR_BAD_TEST_C_INPUT;

	/* Check if input size is valid */
	switch (TEE_ALG_GET_MAIN_ALG(algo)) {
	case TEE_MAIN_ALGO_AES:
		if (size % TEE_AES_BLOCK_SIZE)
			return ERROR_BAD_TEST_C_INPUT;
		break;

	case TEE_MAIN_ALGO_DES:
	case TEE_MAIN_ALGO_DES3:
		if (size % TEE_DES_BLOCK_SIZE)
			return ERROR_BAD_TEST_C_INPUT;
		break;

	default:
		return ERROR_BAD_TEST_C_INPUT;
	}

	return size;
}

static int asymcipher_sizes(uint32_t algo, struct test_param *test)
{
	int outSize;

	/*
	 * Check if input size is valid
	 * return output size if input size is valid
	 * otherwise return negative error
	 */
	switch (algo) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
		/*
		 * Input size in bytes (mLen) <= keysize in bytes (k) - 11
		 * mLen <= (k - 11)
		 */
		if ((int)test->bufsize > (int)((test->keysize / 8) - 11))
			return ERROR_BAD_TEST_SC_INPUT;

		/* Output size is keysize in bytes (k) */
		outSize = (test->keysize / 8);
		break;

	default:
		/* Check input size */
		if (algo & BIT(16)) {
			/* Use MGF */
			/* Input size in bytes (mLen) <= keysize in bytes (k)
			 *       - (2 * hash length (hLen)) - 2
			 * mLen <= (k - 2hLen - 2)
			 */
			int hLen;
			int mLenMax;

			hLen = hash_size(TEE_ALG_GET_INTERNAL_HASH(algo));
			mLenMax = (int)((test->keysize / 8) - (2 * hLen) - 2);

			if ((int)test->bufsize > mLenMax)
				return ERROR_BAD_TEST_SC_INPUT;
		}
		/* Else output size is keysize in bytes (k) */
		outSize = (test->keysize / 8);
		break;
	}

	return outSize;
}

/* Verify Test command */
static int check_test(struct test_param *test)
{
	int     ret;
	bool    found = false;
	uint8_t idx;
	char    *list;
	int		verbosity = test->verbose;

	ret = getcaps_ta();
	if (ret != 0) {
		verbose("Can not get TA Capabalities\n");
		return ret;
	}

	/* Check if Algorithm name is correct */
	list = name_alg_list;
	for (idx = 0; idx < ta_caps.nb_algo; idx++) {
		if (!(strcmp(list, test->alg))) {
			/* Algorithm name is correct */
			found = true;
			break;
		}
		list += strlen(list) + sizeof(char);
	}

	if (!found) {
		vverbose("Algo name [%s] not supported\n", test->alg);
		return ERROR_BAD_TEST_GENERIC;
	}

	/* Check other parameters */
	if (test->keysize == 0) {
		vverbose("Algo name [%s]: key size [%d] not supported\n",
		test->alg, test->keysize);
		return ERROR_BAD_TEST_GENERIC;
	}

	if (test->loop < 2) {
		vverbose(
		"Algo name [%s]: number of iteration [%d] not supported\n",
		test->alg, test->loop);
		return ERROR_BAD_TEST_GENERIC;
	}

	if (test->bufsize == 0) {
		vverbose("Algo name [%s]: buffer size [%d] not supported\n",
			test->alg, test->bufsize);
		return ERROR_BAD_TEST_GENERIC;
	}

	return 0;
}

/* Extract Test command */
static int extract_test(struct test_param *test, char *cmdline,
				uint32_t linenum, int verbosity)
{
	char *elem;

	verbose("\nExtract test [%s]\n", cmdline);
	setdefault_param(test);

	test->verbose = verbosity;

	elem = strtok(cmdline, " ");

	/* First element in the cmdline is algorithm name */
	uppercase(test->alg, elem);
	elem = strtok(NULL, " ");

	while (elem != NULL) {
		if (!strcmp(elem, "-k")) {
			elem = strtok(NULL, " ");
			if (!elem) {
				vverbose(
				"Test %s at line #%d bad key option\n",
				test->alg, linenum);
				return ERROR_BAD_TEST_GENERIC;
			}
			test->keysize = atoi(elem);
		} else if (!strcmp(elem, "-i")) {
			test->in_place = 1;
		} else if (!strcmp(elem, "-n")) {
			elem = strtok(NULL, " ");
			if (!elem) {
				vverbose(
				"Test %s at line #%d bad loop option\n",
				test->alg, linenum);
				return ERROR_BAD_TEST_GENERIC;
			}
			test->loop = atoi(elem);
		} else if (!strcmp(elem, "-r")) {
			test->in_random = 1;
		} else if (!strcmp(elem, "-s")) {
			elem = strtok(NULL, " ");
			if (!elem) {
				vverbose(
				"Test %s at line #%d bad buffer size option\n",
				test->alg, linenum);
				return ERROR_BAD_TEST_GENERIC;
			}
			test->bufsize = strsize_to_bytes(elem);
			if (test->bufsize == (uint32_t)(-1))
				return ERROR_BAD_TEST_GENERIC;
		}

		if (elem)
			elem = strtok(NULL, " ");
	}

	return 0;
}

static int asym_digest(int verbosity, uint32_t alg_id,
				TEEC_SharedMemory *in_shm, size_t *inSize)
{
	/*
	 * Function hash input buffer (in_shm) of length inSize
	 * Result of the hash is copied in the in_shm buffer and inSize
	 * is updated with the new size to be used after
	 */
	TEEC_SharedMemory out_shm;
	TEEC_Operation    op = {0};
	TEEC_Result       res;

	int      ret = 0;
	uint32_t hash_id;
	size_t   outSize;
	uint32_t ret_origin;

	/* Allocate the output buffer function of the hash resulting */
	if (TEE_ALG_GET_MAIN_ALG(alg_id) == TEE_MAIN_ALGO_ECDSA)
		hash_id = TEE_ALG_GET_MAIN_ALG(TEE_ALG_SHA1);
	else
		hash_id = TEE_ALG_GET_DIGEST_HASH(alg_id);

	outSize = hash_size(hash_id);

	verbose("Asymmetric Digest %s input buffer\n", hash_name[hash_id]);

	if (outSize == 0) {
		vverbose("Unable to get hash size of hash id %d\n", hash_id);
		return ERROR_BAD_TEST_DIGEST;
	}

	out_shm.flags  = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	out_shm.buffer = NULL;
	out_shm.size   = outSize;

	res = TEEC_AllocateSharedMemory(&ctx, &out_shm);

	if (check_res(res,
		"TEEC_AllocateSharedMemory Asymmetric digest out_shm") != 0)
		return ERROR_ALLOCATE_SHM;

	/* Prepare Hash algorithm */
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_VALUE_INPUT,
		TEEC_VALUE_OUTPUT,
		TEEC_NONE);
	op.params[0].tmpref.buffer = (char *)hash_name[hash_id];
	op.params[0].tmpref.size   = strlen(hash_name[hash_id]);

	op.params[1].value.a = 0; /* Not used */

	res = TEEC_InvokeCommand(&sess, TA_CRYPTO_PERF_CMD_PREPARE_ALG,
							&op, &ret_origin);

	if (check_res(res,
	"TEEC_InvokeCommand Asymmetric digest prepare algorithm") != 0) {
		ret = ERROR_TA_PREP_ALGO;
		goto asym_digest_exit;
	}

	/* Execute Hash algorithm */
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INOUT,
		TEEC_VALUE_INPUT,
		TEEC_NONE);
	op.params[0].memref.parent = in_shm;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size   = *inSize;
	op.params[1].memref.parent = &out_shm;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size   = outSize;

	/*
	 * First direction
	 */
	op.params[2].value.a = TEE_ALG_HASH_ALGO(hash_id);
	op.params[2].value.b = 0;

	res = TEEC_InvokeCommand(&sess, TA_CRYPTO_PERF_CMD_PROCESS,
							&op, &ret_origin);

	if (check_res(res,
		"TEEC_InvokeCommand Asymmetric digest Process") != 0) {
		if (res == TEE_ERROR_SHORT_BUFFER)
			fprintf(stderr, "Expected output size %zu\n",
					op.params[1].memref.size);
		ret = ERROR_TA_CMD_PROCESS;
		goto asym_digest_exit;
	}

	/* Copy hash result to input buffer and update the size */
	if (*inSize < outSize) {
		/* Input buffer was not enough big */
		TEEC_ReleaseSharedMemory(in_shm);
		in_shm->size = outSize;
		res = TEEC_AllocateSharedMemory(&ctx, in_shm);

		if (check_res(res,
		"TEEC_AllocateSharedMemory Asymmetric digest in_shm") != 0) {
			ret = ERROR_ALLOCATE_SHM;
			goto asym_digest_exit;
		}
	}

	memcpy(in_shm->buffer, out_shm.buffer, outSize);
	*inSize = outSize;

	verbose("Asymmetric Digest Done size: %zu\n", outSize);
asym_digest_exit:
	free_algo(&op);
	TEEC_ReleaseSharedMemory(&out_shm);
	return ret;
}

static int prepare_algo(struct test_param *test,
				uint8_t *reverse, uint32_t *alg_id,
				uint64_t *t_prepare)
{
	TEEC_Operation op = {0};
	TEEC_Result    res;
	uint32_t       ret_origin;
	struct timespec t0, t1;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_VALUE_INPUT,
		TEEC_VALUE_OUTPUT,
		TEEC_NONE);
	op.params[0].tmpref.buffer = test->alg;
	op.params[0].tmpref.size   = strlen(test->alg);

	op.params[1].value.a = test->keysize;
	op.params[1].value.b = test->bufsize;

	get_current_time(&t0);
	res = TEEC_InvokeCommand(&sess, TA_CRYPTO_PERF_CMD_PREPARE_ALG,
							&op, &ret_origin);

	get_current_time(&t1);

	*t_prepare = timespec_diff_ns(&t0, &t1);

	*alg_id  = op.params[2].value.a; // Algorithm ID
	*reverse = op.params[2].value.b; // If 1, reverse operation supported

	if (check_res(res, "TEEC_InvokeCommand prepare algorithm") != 0)
		return ERROR_TA_PREP_ALGO;

	return 0;
}

static int free_algo(TEEC_Operation *op)
{
	TEEC_Result res;
	uint32_t ret_origin;

	res = TEEC_InvokeCommand(&sess, TA_CRYPTO_PERF_CMD_FREE_ALG,
							op, &ret_origin);

	if (check_res(res, "TEEC_InvokeCommand free algorithm") != 0)
		return ERROR_TA_FREE_ALGO;

	return 0;
}

static int run_algo(uint32_t iteration, int verbosity,
			TEEC_Operation *op, struct statistics *stats)
{
	TEEC_Result res;
	uint32_t ret_origin;
	struct timespec t0, t1;
	int      ret;
	uint32_t loop;
	uint64_t diff_t;

	loop = iteration;

	while (loop-- > 0) {
		get_current_time(&t0);

		res = TEEC_InvokeCommand(&sess, TA_CRYPTO_PERF_CMD_PROCESS,
							op, &ret_origin);

		if (check_res(res, "TEEC_InvokeCommand Process") != 0) {
			ret = ERROR_TA_CMD_PROCESS;
			goto run_algo_exit;
		}

		get_current_time(&t1);

		diff_t = timespec_diff_ns(&t0, &t1);
		update_stats(stats, diff_t);

		if ((loop % (iteration / 10)) == 0)
			vverbose(".");
	}

	vverbose("\n");

	ret = free_algo(op);

run_algo_exit:
	return ret;
}

/* Execute Tests */
static int run_test(struct test_param *test, FILE *log)
{
	TEEC_SharedMemory in_shm, out_shm;
	TEEC_Operation    op = {0};
	TEEC_Result       res;
	struct statistics stats_enc, stats_dec;
	uint64_t t_prepare  = 0;
	uint8_t  reverse    = 0; /* Reverse operation */
	uint32_t alg_id;
	int      ret;
	size_t   inSize    = test->bufsize;
	size_t   outSize   = test->bufsize;
	int      verbosity = test->verbose;

	memset(&stats_enc, 0, sizeof(stats_enc));
	memset(&stats_dec, 0, sizeof(stats_dec));
	ret = check_test(test);
	if (ret != 0) {
		verbose("Test not executed because of bad parameters\n");
		goto run_test_exit;
	}

	/* Prepare algorithm (e.g. Keys, working buffer, ...) */
	ret = prepare_algo(test, &reverse, &alg_id, &t_prepare);
	if (ret != 0)
		goto run_test_exit;

	if (TEE_ALG_GET_CLASS(alg_id) == TEE_OPERATION_KEY_DERIVATION)
		inSize = test->keysize / 8;

	/* Allocate shared memory */
	in_shm.flags  = TEEC_MEM_INPUT;
	in_shm.buffer = NULL;
	in_shm.size   = inSize;

	if (test->in_place) {
		/* Use same buffer for input and output */
		in_shm.flags |= TEEC_MEM_OUTPUT;
	}

	res = TEEC_AllocateSharedMemory(&ctx, &in_shm);
	if (check_res(res, "TEEC_AllocateSharedMemory in_shm") != 0) {
		ret = ERROR_ALLOCATE_SHM;
		goto run_test_exit;
	}

	if (test->in_random) {
		ret = read_random(in_shm.buffer, in_shm.size);
		if (ret) {
			ret = ERROR_READ_RANDOM_FILE;
			goto run_test_exit;
		}
	} else {
		memset(in_shm.buffer, 0, in_shm.size);
	}

	switch (TEE_ALG_GET_CLASS(alg_id)) {
	case TEE_OPERATION_CIPHER:
		ret = cipher_size(alg_id, test->bufsize);
		if (ret < 0)
			goto run_test_exit;

		if (TEE_ALG_GET_CHAIN_MODE(alg_id) == TEE_CHAIN_MODE_XTS) {
			if (ret == TEE_AES_BLOCK_SIZE) {
				/* This is just for the final */
				ret *= 2;
			}
		}

		if (TEE_ALG_GET_CHAIN_MODE(alg_id) == TEE_CHAIN_MODE_CTS) {
			if (ret <= (int)(TEE_AES_BLOCK_SIZE * 2)) {
				/* This is just for the final */
				ret += (2 * TEE_AES_BLOCK_SIZE);
			}
		}

		outSize = ret;
		break;

	case TEE_OPERATION_DIGEST:
		/* Digest operation */
		/* Define Output size */
		outSize = hash_size(TEE_ALG_GET_MAIN_ALG(alg_id));

		if (test->in_place) {
			verbose(
			"Digest operation doesn't support test in place\n");
			test->in_place = 0;
		}

		if (outSize == 0) {
			ret = ERROR_BAD_TEST_DIGEST;
			goto run_test_exit;
		}
		break;

	case TEE_OPERATION_ASYMMETRIC_CIPHER:
		/* Asymmetric Cipher operation */
		/* Check Input size and return Output size */
		ret = asymcipher_sizes(alg_id, test);

		if (ret < 0)
			goto run_test_exit;

		if (test->in_place) {
			verbose(
		"Symmetric Cipher operation doesn't support test in place\n");
			test->in_place = 0;
		}

		outSize = ret;
		break;

	case TEE_OPERATION_ASYMMETRIC_SIGNATURE:
		/* Asymmetric Digest operation */
		/*
		 * For this operation, the input message must be digest and
		 * this is the digest which is signed/verified
		 */
		if (test->in_place) {
			verbose(
			"Symmetric Digest doesn't support test in place\n");
			test->in_place = 0;
		}
		/* Force the outSize to be 512 */
		outSize = 512;
		break;

	case TEE_OPERATION_KEY_DERIVATION:
		/* Key Derivation operation */
		outSize = test->keysize / 8;
		break;

	case TEE_OPERATION_AE:
		if (test->in_place) {
			verbose(
			"Authenticated Enc doesn't support test in place\n");
			test->in_place = 0;
		}
		break;

	default:
		break;
	}

	out_shm.flags  = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	out_shm.buffer = NULL;
	/*
	 * Allocate a out buffer size with the max size
	 * between input size (in case of revert operation)
	 * and expected output size of the first direction
	 */
	out_shm.size = (inSize > outSize) ? inSize : outSize;

	if (!(test->in_place)) {
		res = TEEC_AllocateSharedMemory(&ctx, &out_shm);
		if (check_res(res, "TEEC_AllocateSharedMemory out_shm") != 0) {
			ret = ERROR_ALLOCATE_SHM;
			goto run_test_exit;
		}
	}

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INOUT,
		TEEC_VALUE_INPUT,
		TEEC_NONE);

	op.params[0].memref.parent = &in_shm;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size   = inSize;
	op.params[1].memref.parent = (test->in_place) ? &in_shm : &out_shm;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size   = outSize;

	/*
	 * First direction
	 */
	op.params[2].value.a = alg_id;
	op.params[2].value.b = 0;


	/*
	 * Check if an operation must be done before doing the requested
	 * operation.
	 */
	switch (TEE_ALG_GET_CLASS(alg_id)) {
	case TEE_OPERATION_ASYMMETRIC_SIGNATURE:
		/*
		 * Input buffer must be digest and this is the hash
		 * resulting which is signed/verified
		 */
		ret = asym_digest(verbosity, alg_id, &in_shm, &inSize);
		if (ret != 0)
			goto run_test_exit;
		/*
		 * Correct the input buffer in the operation struct
		 */
		op.params[0].memref.parent = &in_shm;
		op.params[0].memref.size   = inSize;
		break;

	default:
		break;
	}

	verbose("\nTest Encryption %s\n", test->alg);
	verbose("In place:  %d\n", test->in_place);
	verbose("In Random: %d\n", test->in_random);
	verbose("Keysize:   %d\n", test->keysize);
	verbose("Loop:      %d\n", test->loop);
	verbose("Size In:   %zu\n", inSize);
	if (!(test->in_place))
		verbose("Size Out:  %zu\n", outSize);

	OPEN_DATA(test->alg);

	stats_enc.data_size = inSize;

	ret = run_algo(test->loop, verbosity, &op, &stats_enc);

	if (ret != 0)
		goto run_test_exit;

	if (!reverse)
		goto run_test_end;

	/*
	 * Other direction
	 */
	op.params[2].value.b = 1;

	/*
	 * Check algo to prepare revert operation
	 */
	switch (TEE_ALG_GET_CLASS(alg_id)) {
	case TEE_OPERATION_ASYMMETRIC_SIGNATURE:
		/*
		 * For Asymmetric signature, the output generated
		 * becomes an input for the verify operation
		 */
		outSize = inSize + op.params[1].memref.size;
		verbose("\nTest Decryption %s\n", test->alg);
		verbose("In place:  %d\n", test->in_place);
		verbose("In Random: %d\n", test->in_random);
		verbose("Keysize:   %d\n", test->keysize);
		verbose("Loop:      %d\n", test->loop);
		verbose("Size In:   %zu\n", outSize);

		break;

	default:
		if (TEE_ALG_GET_CHAIN_MODE(alg_id) == TEE_CHAIN_MODE_XTS) {
			if (inSize == TEE_AES_BLOCK_SIZE) {
				/* This is just for the final */
				outSize = TEE_AES_BLOCK_SIZE;
				inSize *= 2;
			}
		}

		if (TEE_ALG_GET_CHAIN_MODE(alg_id) == TEE_CHAIN_MODE_CTS) {
			if (inSize <= (TEE_AES_BLOCK_SIZE * 2)) {
				/* This is just for the final */
				outSize = inSize;
				inSize += (2 * TEE_AES_BLOCK_SIZE);
			}
		}

		/* Revert in and out parameters */
		op.params[0].memref.size   = outSize;
		op.params[1].memref.size   = inSize;

		/*
		 * If not using same buffer for input and output,
		 * copy out to in for reverse operation
		 */
		if (!(test->in_place))
			memcpy(in_shm.buffer, out_shm.buffer, outSize);

		verbose("\nTest Decryption %s\n", test->alg);
		verbose("In place:  %d\n", test->in_place);
		verbose("In Random: %d\n", test->in_random);
		verbose("Keysize:   %d\n", test->keysize);
		verbose("Loop:      %d\n", test->loop);
		verbose("Size In:   %zu\n", outSize);
		if (!(test->in_place))
			verbose("Size Out:  %zu\n", inSize);
		break;
	}

	stats_dec.data_size = outSize;
	ret = run_algo(test->loop, verbosity, &op, &stats_dec);

	if (ret != 0)
		goto run_test_exit;

run_test_end:
	ret = 0;
	fprintf(stderr, "\nTest Result for %s\n", test->alg);
	fprintf(stderr, "** Preparation (Key Generation) **\n");
	fprintf(stderr, "time=%gμs\n", (double)(t_prepare) / 1000);
	fprintf(stderr, "** Encryption direction **\n");
	fprintf(stderr,
		"min=%gμs max=%gμs mean=%gμs stddev=%gμs (%g MiB/s)\n",
		(stats_enc.min / 1000),
		(stats_enc.max / 1000),
		(stats_enc.m / 1000),
		(stddev(&stats_enc) / 1000),
		mb_per_sec(stats_enc.data_size, stats_enc.m / 1000));

	if (reverse) {
		fprintf(stderr, "** Decryption direction **\n");
		fprintf(stderr,
		"min=%gμs max=%gμs mean=%gμs stddev=%gμs (%g MiB/s)\n",
		(stats_dec.min / 1000),
		(stats_dec.max / 1000),
		(stats_dec.m / 1000),
		(stddev(&stats_dec) / 1000),
		mb_per_sec(stats_dec.data_size, stats_dec.m / 1000));
	}
	fprintf(stderr, "\n");

	print_log_result(log, reverse, &stats_enc, &stats_dec,
			((double)(t_prepare) / 1000));

run_test_exit:
	if (log)
		if (ret != 0)
			fprintf(log, "Execution error 0x%08X\n", ret);

	CLOSE_DATA;

	TEEC_ReleaseSharedMemory(&in_shm);
	TEEC_ReleaseSharedMemory(&out_shm);
	return ret;

}

static int execute_single(struct test_param *test)
{
	int ret;

	ret = open_ta();

	if (ret == 0)
		ret = run_test(test, NULL);

	return ret;
}

static int execute_list(char *inFilename, char *logFilename, int verbosity)
{
	FILE     *infile = NULL;
	FILE     *logfile = NULL;
	uint32_t linenum = 0;
	int      ret = 0;
	char     *cmd = NULL;
	size_t   len = 0;
	ssize_t  read;
	struct test_param test;

	if (logFilename[0])
		verbose("** Execute test file [%s] and log to [%s] **\n\n",
				inFilename, logFilename);
	else
		verbose("** Execute test file [%s] **\n\n", inFilename);

	infile = fopen(inFilename, "r");

	if (!infile) {
		fprintf(stderr, "Open file [%s] error\n", inFilename);
		ret = ERROR_BAD_TEST_GENERIC;
		goto execute_list_exit;
	}

	/* if log file defined, open it in append mode */
	if (logFilename[0]) {
		logfile = fopen(logFilename, "a");

		if (!logfile) {
			fprintf(stderr, "Open log file [%s] error\n",
				logFilename);
			ret = ERROR_BAD_TEST_GENERIC;
			goto execute_list_exit;
		}
	}

	ret = open_ta();
	if (ret != 0)
		goto execute_list_exit;

	print_log_header(logfile);

	/* Read file */
	while ((read = getline(&cmd, &len, infile)) != -1) {
		if (read > 0)
			cmd[read - 1] = '\0';

		if ((read != 0) && (strlen(cmd) != 0)) {
			/* Replace "\n" by '\0' */
			cmd[read - 1] = '\0';
			if (extract_test(&test, cmd, linenum, verbosity) == 0) {
				/* Log test */
				print_log_test(logfile, &test);

				/* Execute the test */
				ret = run_test(&test, logfile);
				if (ret & ERROR_BAD_TEST_MASK)
					verbose(
					"Wrong test definition at line #%d\n\n",
					linenum);
				else if (ret < 0)
					verbose(
				"Test @line #%d execution error %0xX\n\n",
				linenum, ret);
			} else {
				verbose(
			"Test not executed because of bad parameters\n");
				verbose(
			"Wrong test definition at line #%d\n\n", linenum);
			}
		}

		linenum++;
	}

	ret = 0;

	free(cmd);

execute_list_exit:
	if (infile)
		fclose(infile);
	if (logfile) {
		fflush(logfile);
		fsync(fileno(logfile));
		fclose(logfile);
	}

	return ret;
}

/* Helpers */
static void cipher_usage(void)
{
	fprintf(stderr, "\nNB: Cipher operation:\n");
	fprintf(stderr, "Key size:\n");
	fprintf(stderr, "  -AES_xxx: 128, 192 or 256 bits\n");
	fprintf(stderr, "  -DES_xxx: 64 bits\n");
	fprintf(stderr, "  -DES3_xxx: 128 or 192 bits\n");
	fprintf(stderr, "Buffer size:\n");
	fprintf(stderr,
	"  - AES_xxx:  minimum is %ld bytes and must be a multiple of %ld\n",
	TEE_AES_BLOCK_SIZE, TEE_AES_BLOCK_SIZE);
	fprintf(stderr,
	"  - DES_xxx:  minimum is %ld bytes and must be a multiple of %ld\n",
	TEE_AES_BLOCK_SIZE, TEE_DES_BLOCK_SIZE);
	fprintf(stderr,
	"  - DES3_xxx: minimum is %ld bytes and must be a multiple of %ld\n",
	TEE_AES_BLOCK_SIZE, TEE_DES_BLOCK_SIZE);
}

static void asymcipher_usage(void)
{
	fprintf(stderr,
	"\nNB: Buffer size for Asymmetric Cipher operation:\n");
	fprintf(stderr,
	"  - RSAES_PKCS1_V1_5:             mLen <= k - 11\n");
	fprintf(stderr,
	"  - RSAES_PKCS1_OAEP_MGF1_SHAxxx: mLen <= k - 2 * hLen - 2\n");
	fprintf(stderr, "Where mLen = Buffer size in bytes\n");
	fprintf(stderr, "      k    = keysize in bytes\n");
	fprintf(stderr, "      hLen = hash length in bytes\n");
}

static void digest_usage(void)
{
	fprintf(stderr,
	"\nNB: key size for algorithm with Digest operation:\n");
	fprintf(stderr,
	"  - with a hash MD5 to SHA256:    minimum size is 512\n");
	fprintf(stderr,
	"  - with a hash SHA384 to SHA512: minimum size is 1024\n");
	fprintf(stderr,
	"  - ECDSA_PXXX:                   key size is XXX\n");
}

static void mac_usage(void)
{
	fprintf(stderr, "\nNB: key size for MAC operation:\n");
	fprintf(stderr, "  - AES:    size is 128, 192 or 256\n");
	fprintf(stderr, "  - DES:    size is 64\n");
	fprintf(stderr, "  - DES3:   size is 128 or 192\n");
	fprintf(stderr, "  - MD5:    size is 64 to 512\n");
	fprintf(stderr, "  - SHA1:   size is 80 to 512\n");
	fprintf(stderr, "  - SHA224: size is 112 to 512\n");
	fprintf(stderr, "  - SHA256: size is 192 to 1024\n");
	fprintf(stderr, "  - SHA384: size is 256 to 1024\n");
	fprintf(stderr, "  - SHA512: size is 256 to 1024\n");
}

static void keyderive_usage(void)
{
	fprintf(stderr, "\nNB: key size for Key Derivation operation:\n");
	fprintf(stderr, "  - DH:         size is 256 to 2048\n");
	fprintf(stderr, "  - ECDSA_PXXX: key size is XXX\n");
}

static void usage(const char *progname)
{
	fprintf(stderr, "Crypto performance testing tool for OP-TEE\n\n");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t%s -h\n", progname);
	fprintf(stderr, "\t%s -infile test_file [-log log_file] [-v level]\n",
	progname);
	fprintf(stderr,
	"\t%s -alg alg_name [-i] [-n loops] [-r] [-s bufsize] [-v level]\n",
	progname);
	fprintf(stderr, "\t%s -alglist\n", progname);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t-h        Print this help and exit\n");
	fprintf(stderr,
	"  Below options are used to execute all performance tests defined\n");
	fprintf(stderr, "  in the input file.\n");
	fprintf(stderr,
	"\t-infile   Input file defining the list of tests to be run\n");
	fprintf(stderr, "\t-log      Log result file\n");
	fprintf(stderr,
	"  Below options are used to execute a single performance test\n");
	fprintf(stderr,
	"\t-alg      Algorithm name (use option -alglist to get list)\n");
	fprintf(stderr,
	"\t-k        Key size in bits [%d]\n", DEFAULT_KEY_SIZE);
	fprintf(stderr,
	"\t-i        Use same buffer for input and output\n");
	fprintf(stderr,
	"\t-n        Number of iterations (2 minimum) [%d]\n", DEFAULT_LOOP);
	fprintf(stderr,
	"\t-r        Initialize input data with random\n");
	fprintf(stderr,
	"\t-s        Buffer size if no unit in bytes [%d]\n",
	DEFAULT_BUFFER_SIZE);
	fprintf(stderr,
	"\t          Unit can be M for MBytes, K for KBytes\n");
	fprintf(stderr, "\t          E.g -s 1M define a size of 1 MBytes\n");
	fprintf(stderr, "\t-v        Verbose level (1 or 2)\n");
	fprintf(stderr, "\t-alglist  List all Algorithms' name available\n");
	mac_usage();
	cipher_usage();
	asymcipher_usage();
	digest_usage();
	keyderive_usage();
	fprintf(stderr, "\n");
}

static int usage_alg_list(void)
{
	uint8_t idx;
	char    *list;
	int		ret;

	ret = open_ta();
	if (ret != 0)
		return ret;

	/* Print all algorithms name */
	ret =  getcaps_ta();
	if (ret != 0)
		return ret;

	list = name_alg_list;
	fprintf(stderr, "List of Algorithms' name supported\n");

	for (idx = 0; idx < ta_caps.nb_algo; idx++) {
		fprintf(stderr, "\t%s\n", list);
		list += strlen(list) + sizeof(char);
	}

	return 0;
}

int crypto_perf_runner_cmd_parser(int argc, char *argv[])
{
	int  ret;
	int  idx;
	int  verbosity = 0;
	char inputfile[256] = {0};
	char logfile[256] = {0};
	size_t  len;
	struct test_param test_param;

	/* If there is no parameter */
	if (argc < 2) {
		usage(argv[0]);
		return 0;
	}

	/* Parse command line to find if helpers or list of tests */
	for (idx = 1; idx < argc; idx++) {
		if (!strcmp(argv[idx], "-h")) {
			usage(argv[0]);
			return 0;
		}
		if (!strcmp(argv[idx], "-alglist")) {
			ret = usage_alg_list();
			goto exit_err;
		}
		if (!strcmp(argv[idx], "-infile")) {
			len = strlen(argv[idx + 1]);
			if ((idx + 1) == argc)
				goto help;

			if (len > sizeof(inputfile)) {
				fprintf(stderr,
			"Input file name too long, must be %zu caracters max\n",
			sizeof(inputfile));
				usage(argv[0]);
				return 1;
			}

			memcpy(inputfile, argv[idx + 1], len);
			idx += 1; /* Next parameter */
		} else if (!strcmp(argv[idx], "-log")) {
			if ((idx + 1) == argc)
				goto help;

			len = strlen(argv[idx + 1]);
			if (len > sizeof(logfile)) {
				fprintf(stderr,
			"Input file name too long, must be %zu caracters max\n",
			sizeof(logfile));
				usage(argv[0]);
				return 1;
			}

			memcpy(logfile, argv[idx + 1], len);
			idx += 1; /* Next parameter */
		} else if (!strcmp(argv[idx], "-v")) {
			if ((idx + 1) == argc)
				goto help;
			verbosity = atoi(argv[idx + 1]);
			idx += 1; /* Next parameter */
		}
	}

	/* Check if there is a list of test */
	if (inputfile[0]) {
		ret = execute_list(inputfile, logfile, verbosity);
		goto exit_err;
	}

	setdefault_param(&test_param);

	/* Parse command line to find single test parameter */
	for (idx = 1; idx < argc; idx++) {
		if (!strcmp(argv[idx], "-alg")) {
			if ((idx + 1) == argc)
				goto help;

			len = strlen(argv[idx + 1]);
			if (len > sizeof(test_param.alg)) {
				fprintf(stderr, "Algorithm name too long\n");
				goto help;
			}

			/* Copy and convert string to upper case */
			uppercase(test_param.alg, argv[idx + 1]);
			idx += 1; /* Next parameter */
		} else if (!strcmp(argv[idx], "-k")) {
			if ((idx + 1) == argc)
				goto help;

			test_param.keysize = atoi(argv[idx + 1]);
			idx += 1; /* Next parameter */
		} else if (!strcmp(argv[idx], "-i")) {
			test_param.in_place = 1;
		} else if (!strcmp(argv[idx], "-n")) {
			if ((idx + 1) == argc)
				goto help;

			test_param.loop = atoi(argv[idx + 1]);
			idx += 1; /* Next parameter */
		} else if (!strcmp(argv[idx], "-r")) {
			test_param.in_random = 1;
		} else if (!strcmp(argv[idx], "-s")) {
			if ((idx + 1) == argc)
				goto help;

			test_param.bufsize = strsize_to_bytes(argv[idx + 1]);
			if (test_param.bufsize == (uint32_t)(-1))
				goto help;

			idx += 1; /* Next parameter */
		}
	}

	test_param.verbose = verbosity;
	ret = execute_single(&test_param);
	if (ret & ERROR_BAD_TEST_MASK)
		goto print_usage;
	else
		verbose("Test execution returned 0x%08X\n\n", ret);

	goto exit_err;

help:
	ret = ERROR_BAD_TEST_GENERIC;

print_usage:
	usage(argv[0]);

exit_err:
	close_ta(ret);
	return ret;
}
