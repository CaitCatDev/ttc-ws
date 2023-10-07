#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LCWS_VER_MAJ 0
#define LCWS_VER_MIN 1
#define LCWS_VER_VENDOR "cat"

#define LCWS_VER_STR LCWS_VER_MAJ # "." LCWS_VER_MIN # "_" LCWS_VER_VENDOR

#define LCWS_CONTINUATION_FRAME 0x0
#define LCWS_TEXT_FRAME 0x1
#define LCWS_BIN_FRAME 0x2

#define LCWS_CONN_CLOSE_FRAME 0x8
#define LCWS_PING_FRAME 0x9 
#define LCWS_PONG_FRAME 0xa

#define LCWS_FRAME_FINAL 0x80;

enum LCWS_CLOSE_CODES {
	LCWS_CLOSE_NORMAL = 1000,
	LCWS_GOING_AWAY = 1001,
	LCWS_PROTOCOL_ERR = 1002,
	LCWS_INVALID_DATA = 1003,
	LCWS_CLOSE_RES = 1004,
	LCWS_CLOSE_RES2 = 1005,
	LCWS_CLOSE_RES_ABNORMAL_CLOSE = 1006,
	LCWS_DATA_TYPE_ERROR = 1007,
	LCWS_POLICY_VIOLATION = 1008,
	LCWS_MESSAGE_TO_BIG = 1009,
	LCWS_EXT_NOT_SUPPORTED = 1010,
	LCWS_REQUEST_FAILED = 1011,
	LCWS_TLS_FAILURE_RES = 1015,
};

typedef struct lcws_wrreq {
	bool fin;
	bool mask;
	uint8_t res: 3;
	uint8_t opcode: 4;
	size_t len;
	char *data;
} lcws_wrreq_t;

typedef struct lcws_buffer {
	bool fin; /*final part of this message*/
	uint8_t opcode;
	char *data;
	size_t len; /*length of data*/
	char mask[4];
	uint16_t close_code;
} lcws_buffer_t;

typedef struct lcws lcws_t;

#ifndef LCWL_DISABLE_SSL
#include <openssl/ssl.h>

typedef struct lcwss lcwss_t;
#endif

int lcws_write(lcws_t *ws, lcws_wrreq_t request);
lcws_buffer_t *lcws_read(lcws_t *socket);

void lcws_free(lcws_t *ws);
lcws_t *lcws_create_from_socket(int socket, const char *host);
lcws_t *lcws_create_from_host(const char *host, const char *port);

void lcws_buffer_free(lcws_buffer_t *buf);

#ifndef LCWL_DISABLE_SSL

int lcwss_write(lcwss_t *socket, lcws_wrreq_t request);
lcws_buffer_t *lcwss_read(lcwss_t *socket);

void lcwss_free(lcwss_t *ws);
lcwss_t *lcwss_create_from_SSL(SSL *socket, const char *host);
lcwss_t *lcwss_create_from_host(const char *host, const char *port, SSL_CTX *ctx);
#endif
