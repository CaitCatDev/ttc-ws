#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TTC_WS_VER_MAJ 0
#define TTC_WS_VER_MIN 1
#define TTC_WS_VER_VENDOR "cat"

#define TTC_WS_VER_STR TTC_WS_VER_MAJ # "." TTC_WS_VER_MIN # "_" TTC_WS_VER_VENDOR

#define TTC_WS_CONTINUATION_FRAME 0x0
#define TTC_WS_TEXT_FRAME 0x1
#define TTC_WS_BIN_FRAME 0x2

#define TTC_WS_CONN_CLOSE_FRAME 0x8
#define TTC_WS_PING_FRAME 0x9 
#define TTC_WS_PONG_FRAME 0xa

#define TTC_WS_FRAME_FINAL 0x80;

enum TTC_WS_CLOSE_CODES {
	TTC_WS_CLOSE_NORMAL = 1000,
	TTC_WS_GOING_AWAY = 1001,
	TTC_WS_PROTOCOL_ERR = 1002,
	TTC_WS_INVALID_DATA = 1003,
	TTC_WS_CLOSE_RES = 1004,
	TTC_WS_CLOSE_RES2 = 1005,
	TTC_WS_CLOSE_RES_ABNORMAL_CLOSE = 1006,
	TTC_WS_DATA_TYPE_ERROR = 1007,
	TTC_WS_POLICY_VIOLATION = 1008,
	TTC_WS_MESSAGE_TO_BIG = 1009,
	TTC_WS_EXT_NOT_SUPPORTED = 1010,
	TTC_WS_REQUEST_FAILED = 1011,
	TTC_WS_TLS_FAILURE_RES = 1015,
};

typedef struct ttc_ws_wrreq {
	bool fin;
	bool mask;
	uint8_t res: 3;
	uint8_t opcode: 4;
	size_t len;
	char *data;
} ttc_ws_wrreq_t;

typedef struct ttc_ws_buffer {
	bool fin; /*final part of this message*/
	uint8_t opcode;
	char *data;
	size_t len; /*length of data*/
	char mask[4];
	uint16_t close_code;
} ttc_ws_buffer_t;

typedef struct ttc_ws ttc_ws_t;

#ifndef LCWL_DISABLE_SSL
#include <openssl/ssl.h>

typedef struct ttc_wss ttc_wss_t;
#endif

uint16_t ttc_ws_endian_swap16(uint16_t innum);
uint32_t ttc_ws_endian_swap32(uint32_t innum);
uint64_t ttc_ws_endian_swap64(uint64_t innum);

int ttc_ws_write(ttc_ws_t *ws, ttc_ws_wrreq_t request);
ttc_ws_buffer_t *ttc_ws_read(ttc_ws_t *socket);

void ttc_ws_free(ttc_ws_t *ws);
ttc_ws_t *ttc_ws_create_from_socket(int socket, const char *host);
ttc_ws_t *ttc_ws_create_from_host(const char *host, const char *port);

void ttc_ws_buffer_free(ttc_ws_buffer_t *buf);

#ifndef LCWL_DISABLE_SSL

int ttc_wss_write(ttc_wss_t *socket, ttc_ws_wrreq_t request);
ttc_ws_buffer_t *ttc_wss_read(ttc_wss_t *socket);

void ttc_wss_free(ttc_wss_t *ws);
ttc_wss_t *ttc_wss_create_from_SSL(SSL *socket, const char *host);
ttc_wss_t *ttc_wss_create_from_host(const char *host, const char *port, SSL_CTX *ctx);
#endif
