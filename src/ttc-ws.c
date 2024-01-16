#include <string.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <errno.h>

/*networking*/
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include <ttc_ws.h>

/*TODO: Turn into one structure*/
struct ttc_ws {
	pthread_mutex_t rlock, wlock;
	int socket;

	bool closed;
	uint16_t close_code;
};

#ifndef LCWL_DISABLE_SSL

#include <openssl/ssl.h>

struct ttc_wss {
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
typedef struct ttc_ws_frame {
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
	uint8_t mask: 1;
	uint8_t len: 7;

#endif
	uint8_t extdata[];
}__attribute__((packed)) ttc_ws_frame_t;

static const char *ws_handshake_fmt = "GET %s://%s/ HTTP/1.1\n"
	"Sec-WebSocket-Key: %s\r\n"
	"Sec-WebSocket-Version: 13\r\n"
	"Host: %s\r\n"
	"Upgrade: websocket\r\n"
	"Connection: Upgrade\r\n\r\n";

/*Mask our data to mee with the WS RFC format for clients*/
static char *ttc_ws_mask_data(uint8_t *mask_key, char *data, size_t length) {
	char *output = calloc(1, length);
	
	for(size_t ind = 0; ind < length; ++ind) {
		output[ind] = data[ind] ^ mask_key[ind % 4];
	}

	return output;
}

static uint8_t *ttc_random_array(size_t len) {
	size_t index;
	uint8_t *output;

	/*Sanity check the users input*/
	if(len == 0) {
		printf("%s: Invalid parameter passed in\n", __func__);
		return NULL;
	}
	

	output = calloc(sizeof(uint8_t), len);
	if(output == NULL) {
		printf("%s: calloc failed %s\n", __func__, strerror(errno));
		return NULL;
	}

	srand(time(NULL));

	for(index = 0; index < len; ++index) {
		output[index] = ((uint8_t)rand() % 0xff);
	}

	return output;
}

static const char b64table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; 

static size_t ttc_b64_encode_len(size_t lenin) {
	size_t lenout = lenin;
	
	/*Make number cleanly divisible by 3 if it is not already*/
	if(lenout % 3) {
		lenout -= (lenout % 3); 
		lenout += 3;
	}
	
	lenout /= 3; /*3 bytes is 24bits length in to number of blocks*/
	lenout *= 4; /*get actual byte length of output*/
	
	return lenout;
}

char *ttc_b64_encode(const uint8_t *data, size_t len) {
	size_t index, outindex, outlen;
	uint32_t block;
	char *outstr;
	
	if(!data || !len) {
		errno = -EINVAL;
		printf("%s: Invlaid input\n", __func__);
		return NULL;
	}

	outlen = ttc_b64_encode_len(len); /*calc length needed*/
	outstr = calloc(sizeof(char), outlen + 1); /*allocate length +1*/
	
	if(outstr == NULL) {
		printf("%s: calloc error %s\n", __func__, strerror(errno));
		return NULL;
	}

	for(index = 0, outindex = 0; index < len; index += 3, outindex += 4) {
		/*construct a 24-bit int*/
		block = data[index];
		block = index+1 < len ? block << 8 | data[index+1] : block << 8;	
		block = index+2 < len ? block << 8 | data[index+2] : block << 8;
	
		/*output the first two characters*/
		outstr[outindex] = b64table[(block >> 18) & 0x3F];
		outstr[outindex + 1] = b64table[(block >> 12) & 0x3f];
		
		/*Either set the next two characters or pad them if there are none*/
		outstr[outindex + 2] = index + 1 < len ? b64table[(block >> 6) & 0x3F] :  '=';
		outstr[outindex + 3] = index + 2 < len ? b64table[block & 0x3F] :  '=';	
	}
	
	return outstr;
}

/*Create a non SSH webssocket from a socket fd*/
ttc_ws_t *ttc_ws_create_from_socket(int sockfd, const char *host) {
	uint8_t *ws_key_raw;
	char *b64key, *request;
	int length;
	char buf[2048];
	
	ttc_ws_t *ws_out = calloc(1, sizeof(ttc_ws_t));
	if(!ws_out) {
		printf("%s: allocation error %s\n", __func__, strerror(errno));
		return NULL; /*Allocation Error*/
	}

	/* Sockets are fully duplex meaning we can 
	 * read and write at the same time so we need a 
	 * read and a write lock
	 */
	pthread_mutex_init(&ws_out->wlock, NULL);
	pthread_mutex_init(&ws_out->rlock, NULL);

	ws_key_raw = (uint8_t *)ttc_random_array(16);
	if(!ws_key_raw) {
		printf("%s: allocation error %s\n", __func__, strerror(errno));
		free(ws_out);
		return NULL;
	}

	b64key = ttc_b64_encode(ws_key_raw, 16);
	if(!b64key) {
		printf("%s: allocation error %s\n", __func__, strerror(errno));
		free(ws_key_raw);
		free(ws_out);
	}

	length = snprintf(NULL, 0, ws_handshake_fmt, "ws", host, b64key, host);

	request = calloc(1, length + 1);
	if(!request) {
		printf("%s: allocation error %s\n", __func__, strerror(errno));
		free(b64key);
		free(ws_key_raw);
		free(ws_out);
	}

	snprintf(request, length+1, ws_handshake_fmt, "ws", host, b64key, host);

	printf("%s\n", request);
	send(sockfd, request, length, 0);

	recv(sockfd, buf, 2048, 0);

	free(b64key);
	free(ws_key_raw);
	free(request);

	return ws_out;
}

ttc_ws_t *ttc_ws_create_from_host(const char *host, const char *port) {
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


	return ttc_ws_create_from_socket(sockfd, host);
}

void ttc_ws_free(ttc_ws_t *ws) {
	pthread_mutex_destroy(&ws->wlock);
	pthread_mutex_destroy(&ws->rlock);

	close(ws->socket);

	free(ws);
}


int ttc_ws_write(ttc_ws_t *ws, ttc_ws_wrreq_t req) {
	ttc_ws_frame_t *frame;
	size_t len_needed;
	uint8_t *array_mask;
	char *masked_data;
	int ext_pos;

	if(ws->closed) {
		printf("TTC_WS_ERROR: WS is closed\n");
		return 1;
	}
	
	ext_pos = 0;
	len_needed = sizeof(*frame);
	len_needed += req.len > 125 && req.len < UINT16_MAX ? 2 : 0;
	len_needed += req.len > UINT16_MAX ? 8 : 0;
	len_needed += req.mask ? 4 : 0;

	frame = calloc(1, len_needed + 1);
	if(!frame) {
		return 1;
	}

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
		array_mask = ttc_random_array(4);
		masked_data = ttc_ws_mask_data(array_mask, req.data, req.len);
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


ttc_ws_buffer_t *ttc_ws_read(ttc_ws_t *ws) {
	ttc_ws_buffer_t *buffer;
	uint8_t opcode, len;
	uint16_t len16;
	uint64_t len64;

	if(ws == NULL) {
		printf("TTC_WS_ERROR: WS is NULL");
		return NULL;
	}

	if(ws->closed) {
		printf("TTC_WS_ERROR: WS is closed\n");
		return NULL;
	}

	buffer = calloc(1, sizeof(*buffer));
	if(!buffer) {
		printf("TTC_WS_ERROR: allocation error\n");
		return NULL;
	}	

	pthread_mutex_lock(&ws->rlock);

	recv(ws->socket, &opcode, 1, 0);

	recv(ws->socket, &len, 1, 0);


	buffer->fin = opcode & TTC_WS_FRAME_FINAL;
	buffer->opcode = opcode & 0x7f;

	len = len & 0x7f;
	if(len == 126) {
		recv(ws->socket, &len16, 2, 0);	
#if BYTE_ORDER == LITTLE_ENDIAN
		len16 = ttc_ws_endian_swap16(len16);
#endif
		buffer->len = len16;
	} else if(len == 127) {
		recv(ws->socket, &len64, 8, 0);
#if BYTE_ORDER == LITTLE_ENDIAN
		len64 = ttc_ws_endian_swap64(len64);
#endif
		buffer->len = len64;
	} else {
		buffer->len = len;
	}


	if (buffer->opcode == TTC_WS_CONN_CLOSE_FRAME) {
		ws->closed = 1;
	}

	buffer->data = calloc(1, buffer->len + 1);
	if(!buffer->data) {
		printf("TTC_WS_ERROR: buffer data error\n");
		free(buffer);
		return NULL;
	}

	buffer->data[buffer->len] = 0;
	
	recv(ws->socket, buffer->data, buffer->len, 0);

	pthread_mutex_unlock(&ws->rlock);

	buffer->close_code = buffer->data[0] | buffer->data[1] ;

	return buffer;
}

void ttc_ws_buffer_free(ttc_ws_buffer_t *buf) {
	free(buf->data);
	free(buf);
}

#ifndef LCWL_DISABLE_SSL

ttc_ws_buffer_t *ttc_wss_read(ttc_wss_t *ws) {
	ttc_ws_buffer_t *buffer;
	uint8_t opcode, len;
	uint16_t len16;
	uint64_t len64;

	if(ws == NULL) {
		printf("TTC_WS_ERROR: WS is NULL");
		return NULL;
	}

	if(ws->closed) {
		printf("TTC_WS_ERROR: WS is closed\n");
		return NULL;
	}

	buffer = calloc(1, sizeof(*buffer));
	if(!buffer) {
		printf("TTC_WS_ERROR: Allocation Error\n");
		return NULL;
	}

	pthread_mutex_lock(&ws->rlock);

	SSL_read(ws->ssl, &opcode, 1);

	SSL_read(ws->ssl, &len, 1);


	buffer->fin = opcode & TTC_WS_FRAME_FINAL;
	buffer->opcode = opcode & 0x7f;

	len = len & 0x7f;
	if(len == 126) {
		SSL_read(ws->ssl, &len16, 2);	
#if BYTE_ORDER == LITTLE_ENDIAN
		len16 = ttc_ws_endian_swap16(len16);
#endif
		buffer->len = len16;
	} else if(len == 127) {
		SSL_read(ws->ssl, &len64, 8);
#if BYTE_ORDER == LITTLE_ENDIAN
		len64 = ttc_ws_endian_swap64(len64);
#endif
		buffer->len = len64;
	} else {
		buffer->len = len;
	}


	if (buffer->opcode == TTC_WS_CONN_CLOSE_FRAME) {
		ws->closed = 1;
	}

	buffer->data = calloc(1, buffer->len + 1);
	if(!buffer->data) {
		printf("TTC_WS_ERROR: Allocation error\n");
		free(buffer);
		return NULL;
	}

	buffer->data[buffer->len] = 0;
	
	SSL_read(ws->ssl, buffer->data, buffer->len);

	pthread_mutex_unlock(&ws->rlock);

	buffer->close_code = buffer->data[0] | buffer->data[1] ;

	return buffer;
}

int ttc_wss_write(ttc_wss_t *ws, ttc_ws_wrreq_t req) {
	ttc_ws_frame_t *frame;
	size_t len_needed;
	uint8_t *array_mask;
	char *masked_data;
	int ext_pos;

	if(ws->closed) {
		printf("TTC_WS_ERROR: WS is closed\n");
		return 1;
	}

	ext_pos = 0;
	len_needed = sizeof(*frame);
	len_needed += req.len > 125 && req.len < UINT16_MAX ? 2 : 0;
	len_needed += req.len > UINT16_MAX ? 8 : 0;
	len_needed += req.mask ? 4 : 0;

	frame = calloc(1, len_needed + 1);
	if(!frame) {
		printf("TTC_WS_ERROR: (%s)Allocation Error\n", __func__);
		return 1;
	}

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
		array_mask = ttc_random_array(4);
		

		masked_data = ttc_ws_mask_data(array_mask, req.data, req.len);
	

		frame->extdata[ext_pos++] = array_mask[0];
		frame->extdata[ext_pos++] = array_mask[1];
		frame->extdata[ext_pos++] = array_mask[2];
		frame->extdata[ext_pos++] = array_mask[3];
		free(array_mask);
	} else { /*else on the server don't mask at all*/
		array_mask = NULL;
		masked_data = req.data;
	}


	frame->fin = req.fin;
	frame->opcode = req.opcode;
	frame->res = req.res;
	frame->mask = req.mask;
 
	
	pthread_mutex_lock(&ws->wlock);
	SSL_write(ws->ssl, frame, len_needed); 
	SSL_write(ws->ssl, masked_data, req.len);
	pthread_mutex_unlock(&ws->wlock);


	if(req.mask) {
		free(masked_data);
	}
	free(frame);

	return 0;
}

ttc_wss_t *ttc_wss_create_from_SSL(SSL *sslsock, const char *host) {
	uint8_t *ws_key_raw;
	char *b64key, *request;
	int length;
	char buf[2048];
	ttc_wss_t *ws_out = calloc(1, sizeof(ttc_wss_t));
	if(!request) {
		printf("TTC_WS_ERROR: (%s) Allocation Error\n", __func__);
		return NULL;
	}

	ws_out->ssl = sslsock;

	pthread_mutex_init(&ws_out->wlock, NULL);
	pthread_mutex_init(&ws_out->rlock, NULL);

	ws_key_raw = ttc_random_array(16);
	if(!request) {
		printf("TTC_WS_ERROR: (%s) Allocation Error\n", __func__);
		free(ws_out);
		return NULL;
	}

	b64key = ttc_b64_encode(ws_key_raw, 16);
	if(!request) {
		printf("TTC_WS_ERROR: (%s) Allocation Error\n", __func__);
		free(ws_key_raw);
		free(ws_out);
		return NULL;
	}

	length = snprintf(NULL, 0, ws_handshake_fmt, "wss", host, b64key, host);

	request = calloc(1, length + 1);
	if(!request) {
		printf("TTC_WS_ERROR: (%s) Allocation Error\n", __func__);
		free(b64key);
		free(ws_key_raw);
		free(ws_out);
		return NULL;
	}

	snprintf(request, length+1, ws_handshake_fmt, "wss", host, b64key, host);

	SSL_write(sslsock, request, length);

	SSL_read(sslsock, buf, 2048);

	free(b64key);
	free(ws_key_raw);
	free(request);

	return ws_out;
}

void ttc_wss_free(ttc_wss_t *ws) {
	pthread_mutex_destroy(&ws->wlock);
	pthread_mutex_destroy(&ws->rlock);

	SSL_shutdown(ws->ssl);
	SSL_free(ws->ssl);
	
	free(ws);
}

ttc_wss_t *ttc_wss_create_from_host(const char *host, const char *port, SSL_CTX *ctx) {
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

	return ttc_wss_create_from_SSL(ssl, host);
}

#endif

/*byteN refers to that byte position in a multi byte number
 * going left to right
 * E.G. 0x1020 
 * 0x10 would be byte 0 
 * 0x20 would be byte 1
 */
uint16_t ttc_ws_endian_swap16(uint16_t innum) {
	uint16_t byte0, byte1;
	uint16_t ret;

	byte0 = innum >> 8;
	byte1 = innum & 0xff;
	
	ret = byte0 | (byte1 << 8);

	return ret;
}


uint32_t ttc_ws_endian_swap32(uint32_t innum) {
	uint32_t hbyte, lbyte, lmid_byte, hmid_byte;
	uint32_t ret;
	
	hbyte = (innum >> 24) & 0xff;
	hmid_byte = (innum >> 16) & 0xff;
	lmid_byte = (innum >> 8) & 0xff;
	lbyte = (innum) & 0xff;

	ret = hbyte | (hmid_byte << 8) | (lmid_byte << 16) | lbyte << 24;

	return ret;
}

uint64_t ttc_ws_endian_swap64(uint64_t innum) {
	uint64_t byte0, byte1, byte2, byte3, byte4, byte5, byte6, byte7;
	uint64_t ret;
	
	byte0 = (innum >> 56) & 0xff;
	byte1 = (innum >> 48) & 0xff;
	byte2 = (innum >> 40) & 0xff;
	byte3 = (innum >> 32) & 0xff;
	byte4 = (innum >> 24) & 0xff;
	byte5 = (innum >> 16) & 0xff;
	byte6 = (innum >> 8) & 0xff;
	byte7 = innum & 0xff;


	ret = byte0 | byte1 << 8 | byte2 << 16 | byte3 << 24 | 
		byte4 << 32 | byte5 << 40 | byte6 << 48 | byte7 << 56;

	return ret;
}

