#include <xcopy.h>
#include "http_parser.h"
#include "tcpcopy.h"

#define MAX_PATH_SIZE    128
#define MAX_HEADERS      128
#define MAX_HEADER_SIZE  128
#define MAX_BODY_SIZE    4096


int my_header_field_cb(http_parser *p, const char *buf, size_t len);
int my_header_value_cb(http_parser *p, const char *buf, size_t len);
int my_url_cb(http_parser *p, const char *buf, size_t len);
int my_body_cb(http_parser *p, const char *buf, size_t len);
char *get_arg_from_httpbody(const char *body, size_t len, const char *key, size_t klen);

/* http parser state */
typedef struct {
    u_char     path[MAX_PATH_SIZE];
    char       headers[MAX_HEADERS][2][MAX_HEADER_SIZE];
    unsigned int num_headers;
    enum { 
	NONE=0, 
	FIELD, 
	VALUE } last_header;
    u_char     body[MAX_BODY_SIZE];
} http_state_t ;

static http_parser   		*parser;
static http_state_t  		state;
static http_parser_settings 	settings_null = {
   .on_message_begin = 0, 
   .on_header_field = my_header_field_cb,
   .on_header_value = my_header_value_cb,
   .on_url = my_url_cb,
   .on_status = 0,
   .on_body = my_body_cb,
   .on_headers_complete = 0,
   .on_message_complete = 0,
   .on_chunk_header = 0,
   .on_chunk_complete = 0
};


static size_t
my_strnlen(const char *s, size_t maxlen)
{
    const char *p;

    p = strchr(s, '\0');
    if (p == NULL) {
        return maxlen;
    }

    return p - s;
}

static size_t
strlncat(char *dst, size_t len, const char *src, size_t n)
{
    size_t slen;
    size_t dlen;
    size_t rlen;
    size_t ncpy;

    slen = my_strnlen(src, n);
    dlen = my_strnlen(dst, len);

    if (dlen < len) {
        rlen = len - dlen;
        ncpy = slen < rlen ? slen : (rlen - 1);
        memcpy(dst + dlen, src, ncpy);
        dst[dlen + ncpy] = '\0';
    }

    return slen + dlen;
}



int
my_header_field_cb(http_parser *p, const char *buf, size_t len) {

    if (p != parser) {
        printf("http_parser argument wrong\n");
        return -1;
    }

    if (state.last_header != VALUE) {
        state.num_headers++;
    }

    strlncat(state.headers[state.num_headers-1][0],
                 sizeof(state.headers[state.num_headers-1][0]),
                 buf,
                 len);

    state.last_header = FIELD;

    return 0;
}

int
my_header_value_cb(http_parser *p, const char *buf, size_t len) {

    if (p != parser) {
        printf("http_parser argument wrong\n");
        return -1;
    }

    strlncat(state.headers[state.num_headers-1][1],
                 sizeof(state.headers[state.num_headers-1][1]),
                 buf,
                 len);

    state.last_header = VALUE;

    return 0;
}

int
my_url_cb(http_parser *p, const char *buf, size_t len) {

    strlncat(state.path, sizeof(state.path), buf, len);
    return 0;
}



int
my_body_cb(http_parser *p, const char *buf, size_t len) {

    strlncat(state.body, sizeof(state.body), buf, len);
    return 0;
}


int
my_http_parser_init() {

    /* init http_parser state */
    memset(state.path, 0, sizeof(state.path));
    memset(state.headers, 0, sizeof(state.headers));
    memset(state.body, 0, sizeof(state.body));
    state.num_headers = 0;
    state.last_header = NONE;

    parser = malloc(sizeof(http_parser));

    http_parser_init(parser, HTTP_REQUEST);

    return TC_OK;
}

char *
get_arg_from_httpbody(const char *body, size_t len, const char *arg_name, size_t arg_len)
{
    char *p, *q;
    size_t ncpy;
    char dst[128];

    memset(dst, 0, sizeof(dst));

    p = strstr(body, arg_name);
    if (p == NULL) {
        tc_log_info(LOG_ERR, 0, "argument [%s] not proovided", arg_name);
        return NULL;
    } 

    q = strchr(p, '&');
    if (q == NULL) {
        ncpy = len - (p + arg_len + 1 - body);
    } else {
        ncpy = q - (p + arg_len + 1);
    }
    strncpy(dst, p+arg_len+1, ncpy);
    return dst;
}


int 
proc_api_request(tc_event_t *rev)
{
    int                 recv_len, send_len, fd;
    char                rbuf[8192], wbuf[8192];
    struct sockaddr_in  cli_addr;
    socklen_t           cli_addr_len;
    int                 ret, i;
    size_t              parsed;
    char 		*arg;
    int                 replica_num = 1, saved_replica_num;
    

    fd = accept(rev->fd, (struct sockaddr *) &cli_addr, &cli_addr_len);
    if (fd < 0) {
        tc_log_info(LOG_ERR, 0, "accept failed");
        return TC_ERR;
    }

    memset(rbuf, 0, sizeof(rbuf));

    recv_len = recv(fd, rbuf, sizeof(rbuf), 0);

    //ret = do_proc_request(rbuf, &req);
    my_http_parser_init();
    parser->data = fd;

    parsed = http_parser_execute(parser, &settings_null, rbuf, recv_len);
    if (parsed != recv_len) {
        tc_log_info(LOG_ERR, 0, "http_parse size wrong:recv_len=%d  parsed_len=%d", 
			recv_len, parsed);
        return TC_ERR;
    }

    printf("http body:%s\n", state.body);

    arg = get_arg_from_httpbody(state.body, my_strnlen(state.body, sizeof(state.body)), 
		"time", sizeof("time") - 1);
    replica_num = atoi(arg);

    if(replica_num > 1) {
        clt_settings.replica_num = replica_num;
    }

    snprintf(wbuf, sizeof(wbuf), "set replica_num = %d", replica_num);
    send_len = strlen(wbuf);
    send(fd, wbuf, send_len, 0);

    close(fd);
    
    return TC_OK;
}
