/*
 * tci.h
 *
 *  Created on: 05.05.2010
 *      Author: galkag
 *	modified ckyu.han@samsung.com
 */

#ifndef TCI_H_
#define TCI_H_

#ifdef __cplusplus
extern "C"
{
#endif

/*
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
*/

typedef uint32_t tciCommandId_t;
typedef uint32_t tciResponseId_t;
typedef uint32_t tciReturnCode_t;

/* Responses have bit 31 set */
#define RSP_ID_MASK (1U << 31)
#define RSP_ID(cmdId) (((uint32_t)(cmdId)) | RSP_ID_MASK)
#define IS_CMD(cmdId) ((((uint32_t)(cmdId)) & RSP_ID_MASK) == 0)
#define IS_RSP(cmdId) ((((uint32_t)(cmdId)) & RSP_ID_MASK) == RSP_ID_MASK)

/* Return codes of Trustlet commands. */
#define RET_OK              0            /* Set, if processing is error free */
#define RET_ERR_UNKNOWN_CMD 1            /* Unknown command */
#define RET_CUSTOM_START    2
#define RET_ERR_MAP         3
#define RET_ERR_UNMAP       4

/* TCI command header. */
typedef struct {
	tciCommandId_t commandId;	/* Command ID */
} tciCommandHeader_t;

/* TCI response header. */
typedef struct {
	tciResponseId_t     responseId;		/* Response ID (must be command ID | RSP_ID_MASK )*/
	tciReturnCode_t     returnCode;		/* Return code of command */
} tciResponseHeader_t;

#ifdef __cplusplus
}
#endif

#endif /* TCI_H_ */
