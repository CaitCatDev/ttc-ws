#include <utils.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>


/*networking*/
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include <lchttp.h>
#include "lcws.h"

/*TODO: Turn into one structure*/
struct lcws {
	pthread_mutex_t rlock, wlock;
	int socket;

	bool closed;
	uint16_t close_code;
};

#ifndef LCWL_DISABLE_SSL

#include <openssl/ssl.h>

struct lcwss {
	pthread_mutex_t rlock, wlock;
	SSL *ssl;
	
	bool closed;
	uint16_t close_code;
};
#endif

/*this may read a little confusing but on LE machines
 * bitfields start at bit 0. So len: 7 for example is saying
 * bits 0-6 for 7 bit long field. Then mask: 1 as mask is the 
 * 8th bit on that uint8_t;
 *
 * however on BIG endian machines bit 0 typically is the MSB
 * meaning that len: 7 would be same as saying bits 7-1 
 * with mask being equal to bit position 0. Which would make 
 * the data unrecognizeable once sent to another machine 
 */
typedef struct lcws_frame {
#if BYTE_ORDER == LITTLE_ENDIAN

	uint8_t opcode: 4; /*opcode*/
	uint8_t res: 3; /*3 bit reserve/extension field*/
	uint8_t fin: 1; /*1 bit final marker*/
	uint8_t len: 7; /*length*/
	uint8_t mask: 1; /*Data is masked?*/
	
#elif BYTE_ORDER == BIG_ENDIAN
	
	uint8_t fin: 1;
	uint8_t res: 3;
	uint8_t opcode: 4;
	uint8_t fin: 1; 
	uint8_t mask: 1;
	uint8_t len: 7;

#endif
	uint8_t extdata[];
}__attribute__((packed)) lcws_frame_t;

static const char *ws_handshake_fmt = "GET %s://%s/ HTTP/1.1\n"
	"Sec-WebSocket-Key: %s\r\n"
	"Sec-WebSocket-Version: 13\r\n"
	"Host: %s\r\n"
	"Upgrade: websocket\r\n"
	"Connection: Upgrade\r\n\r\n";


char *mask_data(uint8_t *mask_key, char *data, size_t length) {
	char *output = calloc(1, length);
	
	for(size_t ind = 0; ind < length; ++ind) {
		output[ind] = data[ind] ^ mask_key[ind % 4];
	}

	return output;
}

lcws_t *lcws_create_from_socket(int sockfd, const char *host) {
	uint8_t *ws_key_raw;
	char *b64key;
	char *request;
	int length;
	char buf[2048];
	
	lcws_t *ws_out = calloc(1, sizeof(lcws_t));

	pthread_mutex_init(&ws_out->wlock, NULL);
	pthread_mutex_init(&ws_out->rlock, NULL);


	ws_key_raw = (uint8_t *)random_array(16);
	b64key = b64_encode(ws_key_raw, 16);

	length = snprintf(NULL, 0, ws_handshake_fmt, "wss", host, b64key, host);

	request = calloc(1, length + 1);
	snprintf(request, length+1, ws_handshake_fmt, "wss", host, b64key, host);

	printf("%s\n", request); 
	send(sockfd, request, length, 0);

	recv(sockfd, buf, 2048, 0);

	free(b64key);
	free(ws_key_raw);
	free(request);

	return ws_out;
}

lcws_t *lcws_create_from_host(const char *host, const char *port) {
	int sockfd, res;
	struct addrinfo *info;
	
	printf("getaddrinfo(%s, %s, NULL, %p);", host, port, &info);

	res = getaddrinfo(host, port, NULL, &info);
	if(res != 0) {
		printf("%s(%d)(%s): %m\n", __FUNCTION__, __LINE__, gai_strerror(res));
		return NULL;
	}

	sockfd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	if(sockfd < 0) {
		printf("%s(%d): %m\n", __FUNCTION__, __LINE__);
		freeaddrinfo(info);
		return NULL;	
	}

	res = connect(sockfd, info->ai_addr, (int)info->ai_addrlen);
	freeaddrinfo(info);
	if(res != 0) {
		printf("%s(%d): %m\n", __FUNCTION__, __LINE__);
		close(sockfd);
		return NULL;	
	}


	return lcws_create_from_socket(sockfd, host);
}

void lcws_free(lcws_t *ws) {
	pthread_mutex_destroy(&ws->wlock);
	pthread_mutex_destroy(&ws->rlock);

	close(ws->socket);

	free(ws);
}


int lcws_write(lcws_t *ws, lcws_wrreq_t req) {
	lcws_frame_t *frame;
	size_t len_needed;
	uint8_t *array_mask;
	char *masked_data;
	int ext_pos;

	if(ws->closed) {
		printf("LCWS_ERROR: WS is closed\n");
		return 1;
	}
	
	ext_pos = 0;
	len_needed = sizeof(*frame);
	len_needed += req.len > 125 && req.len < UINT16_MAX ? 2 : 0;
	len_needed += req.len > UINT16_MAX ? 8 : 0;
	len_needed += req.mask ? 4 : 0;

	frame = calloc(1, len_needed + 1);

	if(req.len > 125 && req.len < UINT16_MAX) {
		frame->len = 126;
		frame->extdata[ext_pos++] = (req.len >> 8) & 0xff;
		frame->extdata[ext_pos++] = (req.len) & 0xff;
	} else if(req.len > UINT16_MAX) {
		frame->len = 127;
	} else {
		frame->len = req.len;
	}

	/*Mask the input data if mask is set(Client)*/
	if(req.mask) {
	
		/*generate a random data mask*/
		array_mask = random_array(4);
		

		masked_data = mask_data(array_mask, req.data, req.len);
	} else { /*else on the server don't mask at all*/
		array_mask = NULL;
		masked_data = req.data;
	}


	frame->extdata[ext_pos++] = array_mask[0];
	frame->extdata[ext_pos++] = array_mask[1];
	frame->extdata[ext_pos++] = array_mask[2];
	frame->extdata[ext_pos++] = array_mask[3];

	frame->fin = req.fin;
	frame->opcode = req.opcode;
	frame->res = req.res;
	frame->mask = req.mask;
 
	
	pthread_mutex_lock(&ws->wlock);
	send(ws->socket, frame, len_needed, 0); 
	send(ws->socket, masked_data, req.len, 0);
	pthread_mutex_unlock(&ws->wlock);


	if(req.mask) {
		free(array_mask);
		free(masked_data);
	}
	free(frame);

	return 0;
}


lcws_buffer_t *lcws_read(lcws_t *ws) {
	lcws_buffer_t *buffer;
	uint8_t opcode, len;
	uint16_t len16;
	uint64_t len64;

	if(ws == NULL) {
		printf("LCWS_ERROR: WS is NULL");
		return NULL;
	}

	if(ws->closed) {
		printf("LCWS_ERROR: WS is closed\n");
		return NULL;
	}

	buffer = calloc(1, sizeof(*buffer));
	
	pthread_mutex_lock(&ws->rlock);

	recv(ws->socket, &opcode, 1, 0);

	recv(ws->socket, &len, 1, 0);


	buffer->fin = opcode & LCWS_FRAME_FINAL;
	buffer->opcode = opcode & 0x7f;

	len = len & 0x7f;
	if(len == 126) {
		recv(ws->socket, &len16, 2, 0);	
		len16 = endian_swap16(len16);
		buffer->len = len16;
	} else if(len == 127) {
		recv(ws->socket, &len64, 8, 0);
		len64 = endian_swap64(len64);
		buffer->len = len64;
	} else {
		buffer->len = len;
	}


	if (buffer->opcode == LCWS_CONN_CLOSE_FRAME) {
		ws->closed = 1;
	}

	buffer->data = calloc(1, buffer->len + 1);
	buffer->data[buffer->len] = 0;
	
	recv(ws->socket, buffer->data, buffer->len, 0);

	pthread_mutex_unlock(&ws->rlock);

	buffer->close_code = buffer->data[0] | buffer->data[1] ;

	return buffer;
}

#ifndef LCWL_DISABLE_SSL

lcws_buffer_t *lcwss_read(lcwss_t *ws) {
	lcws_buffer_t *buffer;
	uint8_t opcode, len;
	uint16_t len16;
	uint64_t len64;

	if(ws == NULL) {
		printf("LCWS_ERROR: WS is NULL");
		return NULL;
	}

	if(ws->closed) {
		printf("LCWS_ERROR: WS is closed\n");
		return NULL;
	}

	buffer = calloc(1, sizeof(*buffer));
	
	pthread_mutex_lock(&ws->rlock);

	SSL_read(ws->ssl, &opcode, 1);

	SSL_read(ws->ssl, &len, 1);


	buffer->fin = opcode & LCWS_FRAME_FINAL;
	buffer->opcode = opcode & 0x7f;

	len = len & 0x7f;
	if(len == 126) {
		SSL_read(ws->ssl, &len16, 2);	
		len16 = endian_swap16(len16);
		buffer->len = len16;
	} else if(len == 127) {
		SSL_read(ws->ssl, &len64, 8);
		len64 = endian_swap64(len64);
		buffer->len = len64;
	} else {
		buffer->len = len;
	}


	if (buffer->opcode == LCWS_CONN_CLOSE_FRAME) {
		ws->closed = 1;
	}

	buffer->data = calloc(1, buffer->len + 1);
	buffer->data[buffer->len] = 0;
	
	SSL_read(ws->ssl, buffer->data, buffer->len);

	pthread_mutex_unlock(&ws->rlock);

	buffer->close_code = buffer->data[0] | buffer->data[1] ;

	return buffer;
}

int lcwss_write(lcwss_t *ws, lcws_wrreq_t req) {
	lcws_frame_t *frame;
	size_t len_needed;
	uint8_t *array_mask;
	char *masked_data;
	int ext_pos;

	if(ws->closed) {
		printf("LCWS_ERROR: WS is closed\n");
		return 1;
	}
	
	ext_pos = 0;
	len_needed = sizeof(*frame);
	len_needed += req.len > 125 && req.len < UINT16_MAX ? 2 : 0;
	len_needed += req.len > UINT16_MAX ? 8 : 0;
	len_needed += req.mask ? 4 : 0;

	frame = calloc(1, len_needed + 1);

	if(req.len > 125 && req.len < UINT16_MAX) {
		frame->len = 126;
		frame->extdata[ext_pos++] = (req.len >> 8) & 0xff;
		frame->extdata[ext_pos++] = (req.len) & 0xff;
	} else if(req.len > UINT16_MAX) {
		frame->len = 127;
	} else {
		frame->len = req.len;
	}

	/*Mask the input data if mask is set(Client)*/
	if(req.mask) {
	
		/*generate a random data mask*/
		array_mask = random_array(4);
		

		masked_data = mask_data(array_mask, req.data, req.len);
	} else { /*else on the server don't mask at all*/
		array_mask = NULL;
		masked_data = req.data;
	}


	frame->extdata[ext_pos++] = array_mask[0];
	frame->extdata[ext_pos++] = array_mask[1];
	frame->extdata[ext_pos++] = array_mask[2];
	frame->extdata[ext_pos++] = array_mask[3];

	frame->fin = req.fin;
	frame->opcode = req.opcode;
	frame->res = req.res;
	frame->mask = req.mask;
 
	
	pthread_mutex_lock(&ws->wlock);
	printf("LOCKED\n");
	SSL_write(ws->ssl, frame, len_needed); 
	SSL_write(ws->ssl, masked_data, req.len);
	pthread_mutex_unlock(&ws->wlock);


	if(req.mask) {
		free(array_mask);
		free(masked_data);
	}
	free(frame);

	return 0;
}

lcwss_t *lcwss_create_from_SSL(SSL *sslsock, const char *host) {
	uint8_t *ws_key_raw;
	char *b64key;
	char *request;
	int length;
	char buf[2048];
	lcwss_t *ws_out = calloc(1, sizeof(lcwss_t));

	ws_out->ssl = sslsock;

	pthread_mutex_init(&ws_out->wlock, NULL);
	pthread_mutex_init(&ws_out->rlock, NULL);

	ws_key_raw = (uint8_t *)random_array(16);
	b64key = b64_encode(ws_key_raw, 16);

	length = snprintf(NULL, 0, ws_handshake_fmt, "wss", host, b64key, host);

	request = calloc(1, length + 1);
	snprintf(request, length+1, ws_handshake_fmt, "wss", host, b64key, host);

	printf("%s\n", request); 
	SSL_write(sslsock, request, length);

	SSL_read(sslsock, buf, 2048);

	free(b64key);
	free(ws_key_raw);
	free(request);

	return ws_out;
}

void lcwss_free(lcwss_t *ws) {
	pthread_mutex_destroy(&ws->wlock);
	pthread_mutex_destroy(&ws->rlock);

	SSL_shutdown(ws->ssl);
	SSL_free(ws->ssl);
	
	free(ws);
}

lcwss_t *lcwss_create_from_host(const char *host, const char *port, SSL_CTX *ctx) {
	SSL *ssl;
	int sockfd, res;
	struct addrinfo *info;
	
	printf("getaddrinfo(%s, %s, NULL, %p);", host, port, &info);

	res = getaddrinfo(host, port, NULL, &info);
	if(res != 0) {
		printf("%s(%d)(%s): %m\n", __FUNCTION__, __LINE__, gai_strerror(res));
		return NULL;
	}

	sockfd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	if(sockfd < 0) {
		printf("%s(%d): %m\n", __FUNCTION__, __LINE__);
		freeaddrinfo(info);
		return NULL;	
	}

	res = connect(sockfd, info->ai_addr, (int)info->ai_addrlen);
	freeaddrinfo(info);
	if(res != 0) {
		printf("%s(%d): %m\n", __FUNCTION__, __LINE__);
		close(sockfd);
		return NULL;	
	}

	ssl = SSL_new(ctx);
	if(ssl == NULL) {
		close(sockfd);
		printf("%s(%d): %m\n", __FUNCTION__, __LINE__);
		return NULL;	
	}
	
	SSL_set_fd(ssl, sockfd);

	res = SSL_connect(ssl);
	if(res != 1) {
		close(sockfd);
		SSL_free(ssl);
		printf("%s(%d): %m\n", __FUNCTION__, __LINE__);
		return NULL;
	}

	return lcwss_create_from_SSL(ssl, host);
}

#endif

