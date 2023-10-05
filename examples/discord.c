#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <json-c/json.h>
#include <stdlib.h>
#include <unistd.h>

#include <pthread.h>

#include "lcws.h"
#include "utils.h"
#include <signal.h>

int setup_socket(const char *host, const char *port) {
	int res, sockfd;
	struct addrinfo *info = NULL;

	res = getaddrinfo(host, port, NULL, &info);
	if(res != 0) {
		printf("getaddrinfo: %s\n", gai_strerror(res));
		return -1;
	}
	
	sockfd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	if(sockfd < 0) {
		freeaddrinfo(info);
		printf("socket: %m\n");
		return -1;
	}

	res = connect(sockfd, info->ai_addr, (int)info->ai_addrlen);
	freeaddrinfo(info);
	if(res != 0) {
		printf("connect: %m\n");
		return -1;
	}

	return sockfd;
}

SSL_CTX *ssl_init() {
	SSL_CTX *ctx;

	SSL_library_init();

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_client_method());

	return ctx;
}

/*IN real code Error checks should be preformed but 
 * are left out for the sake of berevity*/
SSL *ssl_setup(SSL_CTX *ctx, int fd) {
	SSL *ssl;

	ssl = SSL_new(ctx);
	
	SSL_set_fd(ssl, fd);

	SSL_connect(ssl);

	return ssl;
}

void discord_identify(lcwss_t *wss, const char *discord_token) {
	json_object *login, *data, *opcode, *token, 
				*properties, *os, *browser, *device, *intents,
				*presence, *status, *afk, *activities,
				*name, *type, *activity, *state, *emoji,
				*emjname;
	lcws_wrreq_t login_request;

	activities = json_object_new_array();
	name = json_object_new_string("I love C");
	state = json_object_new_string("❤️ I love C");
	emoji = json_object_new_object();
	emjname = json_object_new_string("heart");
	json_object_object_add(emoji, "name", emjname);
	type = json_object_new_int(4);

	status = json_object_new_string("online");
	presence = json_object_new_object();
	afk = json_object_new_boolean(0);
	
	json_object_object_add(presence, "activities", activities);
	json_object_object_add(presence, "status", status);
	json_object_object_add(presence, "afk", afk);

	activity = json_object_new_object();

	json_object_object_add(activity, "name", name);
	json_object_object_add(activity, "type", type);
	json_object_object_add(activity, "emoji", emoji);
	json_object_object_add(activity, "state", state);
	json_object_array_add(activities, activity);


	login = json_object_new_object();
	data = json_object_new_object();
	opcode = json_object_new_int(2);
	printf("%s", discord_token);
	token = json_object_new_string(discord_token);

	properties = json_object_new_object();
	os = json_object_new_string("Linux");
	browser = json_object_new_string("ttc-cbot");
	device = json_object_new_string("ttc-cbot");
	
	intents = json_object_new_int(0);

	json_object_object_add(properties, "os", os);
	json_object_object_add(properties, "browser", browser);
	json_object_object_add(properties, "device", device);

	
	json_object_object_add(data, "token", token);
	json_object_object_add(data, "properties", properties);
	json_object_object_add(data, "presence", presence);
	json_object_object_add(data, "intents", intents);
	
	json_object_object_add(login, "op", opcode);
	json_object_object_add(login, "d", data);
	
	login_request.res = 0;
	login_request.opcode = 1;
	login_request.fin = 1;
	login_request.mask = 1;
	login_request.data = json_object_to_json_string(login);
	login_request.len = strlen(json_object_to_json_string(login));
	
	printf("%s\n", json_object_to_json_string(login));

	lcwss_write(wss, login_request);

	json_object_put(login);
}

void discord_heartbeat(lcwss_t *wss, int sequence) {
	static json_object *op, *d, *heartbeat;
	static lcws_wrreq_t heartreq;

	heartbeat = json_object_new_object();
	d = json_object_new_int(sequence);
	op = json_object_new_int(1);
	json_object_object_add(heartbeat, "op", op);
	json_object_object_add(heartbeat, "d", d);

	heartreq.mask = 1;
	heartreq.res = 0;
	heartreq.fin = 1;
	heartreq.opcode = 1;
	heartreq.data = json_object_get_string(heartbeat);
	heartreq.len = strlen(heartreq.data);

	lcwss_write(wss, heartreq);
	json_object_put(heartbeat);
}

char *token_from_file(const char *path) {
	FILE *fp = fopen(path, "r");
	long len;
	char *token;

	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	rewind(fp);

	token = calloc(1, len + 1);
	fread(token, 1, len, fp);

	if(token[len - 1] == '\n') {
		token[len - 1] = '\0';
	}

	fclose(fp);
	return token;
}

void *heart(void *vargp) {
	while(1) {
		sleep(40);
		discord_heartbeat(vargp, 1);
	}
	
}

typedef struct {
	const char *resumeurl;
	const char *token;
	const char *sessionid;
	SSL_CTX *sslctx;
	lcwss_t *wss;
} discord_ctx;

static lcwss_t *gwss;

void discord_reconnect(discord_ctx *ctx) {
	json_object *resume, *op, *seq, *d, *sessionid, *token;
	lcws_wrreq_t wreq;

	resume = json_object_new_object();
	sessionid = json_object_new_string(ctx->sessionid);
	token = json_object_new_string(ctx->token);
	op = json_object_new_int(6);
	seq = json_object_new_int(1);
	d = json_object_new_object();

	json_object_object_add(d, "token", token);
	json_object_object_add(d, "session_id", sessionid);
	json_object_object_add(d, "seq", seq);
	json_object_object_add(resume, "op", op);
	json_object_object_add(resume, "d", d);
	
	lcwss_free(gwss);

	lcwss_t *wss = lcwss_create_from_host(ctx->resumeurl, "443", ctx->sslctx);
	
	wreq.data = json_object_to_json_string(resume);
	wreq.len = strlen(json_object_to_json_string(resume));
	wreq.fin = 1;
	wreq.mask = 1;
	wreq.res = 0;
	wreq.opcode = LCWS_TEXT_FRAME;
	
	printf("Resuming: %s\n", wreq.data);

	lcwss_write(wss, wreq);

	json_object_put(resume);
	gwss = wss;
}

void parse_message(lcws_buffer_t *buffer, discord_ctx *ctx, pthread_t *heartthread) {
	json_object *response = json_tokener_parse(buffer->data);
	json_object *op = json_object_object_get(response, "op");
	int opint = json_object_get_int(op);
	
	if(opint == 7) {
		pthread_cancel(*heartthread);
		discord_reconnect(ctx);
		printf("LENGTH: %lu\n%s\n", buffer->len, buffer->data);
		pthread_create(heartthread, NULL, heart, gwss);
	} else if(opint == 11) {
		printf("Heartbeat ACK\n");
	} else { 
		printf("%s\n", buffer->data);
		printf("%s\n", buffer->data);
	}
	
	json_object_put(response);
}

int running = 1;

void sigint_handle(int signo) {
	running = 0;
}

void *ws_read(void *vargp) {
	discord_ctx *ctx = vargp;
	lcws_buffer_t *buffer;
	pthread_t heartthread;

	gwss = ctx->wss;
	pthread_create(&heartthread, NULL, heart, ctx->wss);

	while(running) {

		buffer = lcwss_read(gwss);
	
	
		parse_message(buffer, ctx, &heartthread);
		
		if(buffer->opcode == LCWS_CONN_CLOSE_FRAME) {
			printf("%d\n", endian_swap16(((uint16_t*)buffer->data)[0]));	
			

			if(endian_swap16(((uint16_t*)buffer->data)[0]) == 1001) {
				printf("Attempting Reconnect\n");
				pthread_cancel(heartthread);
				discord_reconnect(ctx);
				pthread_create(&heartthread, NULL, heart, gwss);
			
			} else {
				pthread_exit(NULL);
			}
		}
		free(buffer->data);
		free(buffer);
	}
	pthread_exit(NULL);
}

int main(int argc, char **argv) {
	SSL_CTX *ctx;
	char *token;
	SSL *ssl;
	int sock;
	pthread_t readthread;

	if(argc < 2) {
		printf("Discord Example Usage:\n"
				"%s <TOKEN_FILE>\n", argv[0]);
		return 1;
	}

	token = token_from_file(argv[1]);

    ctx = ssl_init();

	sock = setup_socket("gateway.discord.gg", "443");

	ssl = ssl_setup(ctx, sock);

	gwss = lcwss_create_from_SSL(ssl, "gateway.discord.gg");

	char buf[2048];

	int len = SSL_read(ssl, buf, 2047);
	buf[len] = '\0';

	printf("%s\n", buf);

	discord_identify(gwss, token);

	lcws_buffer_t *buffer = lcwss_read(gwss);
	printf("%s\n", buffer->data);
	json_object *ready, *d, *resumeurl, *sessionid;
	
	ready = json_tokener_parse(buffer->data);
	d = json_object_object_get(ready, "d");
	resumeurl = json_object_object_get(d, "resume_gateway_url");
	sessionid = json_object_object_get(d, "session_id");

	discord_ctx dctx;

	dctx.wss = gwss;
	dctx.token = token;
	dctx.sslctx = ctx;
	dctx.resumeurl = &json_object_get_string(resumeurl)[6];
	dctx.sessionid = json_object_get_string(sessionid);
	
	__builtin_dump_struct(&dctx, &printf);

	signal(SIGINT, sigint_handle);

	free(buffer->data);
	free(buffer);

	pthread_create(&readthread, NULL, ws_read, &dctx);


	pthread_join(readthread, NULL);

	json_object_put(ready);
	free(token);
	lcwss_free(gwss);
	SSL_CTX_free(ctx);

	return 0;
}
