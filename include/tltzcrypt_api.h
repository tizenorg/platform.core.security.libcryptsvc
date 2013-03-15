/*
 *
 */
#ifndef TLTZCRYPT_API_H_
#define TLTZCRYPT_API_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "tci.h"

/* Command ID's for communication Trustlet Connector -> Trustlet. */
#define CMD_ENCRYPT_TZ_CRYPT		0x00000001
#define CMD_DECRYPT_TZ_CRYPT		0x00000002
#define CMD_WRAPIDENTITY_TZ_CRYPT			0x00000003
#define CMD_UNWRAPIDENTITY_TZ_CRYPT			0x00000004
#define CMD_HASH_TZ_CRYPT				0x00000005

/* Return codes */
#define	RET_TL_OK			0x00000000

/* Error codes */
#define RET_ERR_ENCRYPT_TZ_CRYPT	0x10000001
#define RET_ERR_DECRYPT_TZ_CRYPT	0x10000002
#define RET_ERR_WRAPIDENTITY_TZ_CRYPT		0x10000003
#define RET_ERR_UNWRAPIDENTITY_TZ_CRYPT		0x10000004
#define RET_ERR_HASH_TZ_CRYPT		0x10000005

/* Termination codes */
#define EXIT_ERROR                      ((uint32_t)(-1))

#define SIZE_CHUNK		1024
#define SIZE_SECUREOBJECT	1116	// SO SIZE for 1024 byte (predefined)
#define SIZE_HASHAPPIDENTITY		32
#define SIZE_WRAPAPPIDENTITY		124

/* TCI message data. */
typedef struct {
	uint32_t	id;
	//uint32_t	data_len;
	//uint8_t	*data_ptr;
	//uint8_t	data[MAX_DATA_LEN];
} tci_cmd_t;

typedef struct {
	uint32_t	id;
	uint32_t	return_code;
	//uint32_t	data_len;
	//uint8_t	*data_ptr;
	//uint8_t	data[MAX_DATA_LEN];
} tci_resp_t;


typedef union {
	uint8_t input_data[SIZE_CHUNK];
        uint8_t output_data[SIZE_SECUREOBJECT];
} buffer_t;

typedef union {
	uint8_t hash_identity[SIZE_HASHAPPIDENTITY];
	uint8_t wrap_identity[SIZE_WRAPAPPIDENTITY];
} identity_t;

typedef struct {
	union {
		tci_cmd_t			cmd;			/* Command message structure */
		tci_resp_t			resp;			/* Response message structure */
	};
	uint32_t pData;
	uint32_t pLen;
	uint32_t cData;
	uint32_t cLen;
} tciMessage_t;

/* Trustlet UUID. */
#define TL_TZ_CRYPT_UUID { { 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 } }

#ifdef __cplusplus
}
#endif

#endif /* TLTZCRYPT_API_H_ */
