#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>

#include "log.h"
#include "network_funcs.h"
#include "event.h"
#include "proxy_qat.h"

#define PROXY_CERT_DIR "/Users/zhanglong/ca"

#define PROXY_SELF_CERT_KEY_PATH PROXY_CERT_DIR "/users/client.key"
#define PROXY_SELF_CERT_PATH PROXY_CERT_DIR "/users/client.crt"

#define PROXY_CA_CERT_PATH PROXY_CERT_DIR "/private/ca.crt"
#define PROXY_CA_KEY_PATH PROXY_CERT_DIR "/private/ca.key"

#define HOST_STR_LEN 256
#define PORT_STR_LEN sizeof("65535")
#define RECV_BUF_LEN 4096
#define PROXY_CONNECT_REQUEST_PREFIX "CONNECT "
#define PROXY_SEND_BUF 4096

#define PROXY_TIMEOUT 10

#define PROXY_CONNECTED "HTTP/1.1 200 Connection Established\r\n\r\n"

#define PROXY_SSL_ERROR ERR_error_string(ERR_get_error(), NULL)

extern struct event_scheduler *proxy_get_event_scheduler();

extern time_t g_proxy_time;

volatile int nr_ssl_connection = 0;

SSL_CTX *self_ssl_ctx;
static SSL *m_peek_sni_ssl;
static BIO *m_peek_sni_ssl_in_bio;

struct proxy_opts {
	int peep;
	int async;

	X509 *cacrt;
	EVP_PKEY *cakey;
	EVP_PKEY *key;
	STACK_OF(X509) *chain;
};

struct proxy_opts m_proxy_opts = {
	1,
	0,
	NULL,
	NULL,
	NULL,
	NULL,
};

enum ssl_want {
	SSL_WANT_READ,
	SSL_WANT_WRITE,
	SSL_WANT_ASYNC,
};

enum ssl_dir {
	SSL_DIR_2C,
	SSL_DIR_2S,
};

struct ssl_state {
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *ssl_bio;
	BIO *in_bio;
	BIO *out_bio;

	X509 *crt;

	enum ssl_want want;
	enum ssl_dir dir;
	int need_finish;
	int handshaked;
};

#define proxy_log(_ps, _dir, _lv, _fmt, arg...)                            \
do {                                                                       \
        if (SSL_DIR_2C == (_dir))                                          \
                log_printf(_lv, "(%s->%s) %s->%s fd %d ref %d "_fmt,       \
                           sockaddr_string(&(_ps)->cli),                   \
                           sockaddr_string1(&(_ps)->cself),                \
                           sockaddr_string2(&(_ps)->sself),                \
                           sockaddr_string3(&(_ps)->svr),                  \
                           (_ps)->cli_fd, (_ps)->ref, ##arg);              \
        else                                                               \
                log_printf(_lv, "%s->%s (%s->%s) fd %d ref %d "_fmt,       \
                           sockaddr_string(&(_ps)->cli),                   \
                           sockaddr_string1(&(_ps)->cself),                \
                           sockaddr_string2(&(_ps)->sself),                \
                           sockaddr_string3(&(_ps)->svr),                  \
                           (_ps)->cli_fd, (_ps)->ref, ##arg);              \
} while(0)

#define proxy_debug(_ps, _dir, _fmt, arg...) \
proxy_log(_ps, _dir, LOG_LV_DEBUG,_fmt, ##arg)

#define proxy_info(_ps, _dir, _fmt, arg...) \
proxy_log(_ps, _dir, LOG_LV_INFO,_fmt, ##arg)

#define proxy_error(_ps, _dir, _fmt, arg...) \
proxy_log(_ps, _dir, LOG_LV_ERROR,_fmt, ##arg)

#define proxy_debug_cli(_ps, _fmt, arg...) \
proxy_log(_ps, SSL_DIR_2C, LOG_LV_DEBUG,_fmt, ##arg)

#define proxy_info_cli(_ps, _fmt, arg...) \
proxy_log(_ps, SSL_DIR_2C, LOG_LV_INFO,_fmt, ##arg)

#define proxy_error_cli(_ps, _fmt, arg...) \
proxy_log(_ps, SSL_DIR_2C, LOG_LV_ERROR,_fmt, ##arg)

#define proxy_debug_svr(_ps, _fmt, arg...) \
proxy_log(_ps, SSL_DIR_2S, LOG_LV_DEBUG,_fmt, ##arg)

#define proxy_info_svr(_ps, _fmt, arg...) \
proxy_log(_ps, SSL_DIR_2S, LOG_LV_INFO,_fmt, ##arg)

#define proxy_error_svr(_ps, _fmt, arg...) \
proxy_log(_ps, SSL_DIR_2S, LOG_LV_ERROR,_fmt, ##arg)

struct proxy_event {
	struct list_head node;
	struct event *e;
	struct proxy_state *ps;

	int (*handler)(struct proxy_state *);

	int async;
	struct event *async_other;

	const char *what;
};

struct proxy_state {
	struct sockaddr cli; // 客户端地址
	struct sockaddr cself; // 与客户端连接的己方地址
	struct sockaddr sself; // 与服务器连接的己方地址
	struct sockaddr svr; // 服务器地址

	int peep; // 是否看客户端与服务器的明文内容，会伪造服务器证书，客户端会告警
	int ref;
	int cli_fd;
	time_t cli_active;
	int svr_fd;
	time_t svr_active;
	char host[HOST_STR_LEN];
	char port[PORT_STR_LEN];
	char sni[HOST_STR_LEN];

	struct list_head events;

	struct ssl_state *client;
	struct ssl_state *server;
};

void proxy_ref_ps(struct proxy_state *ps)
{
	ps->ref += 1;
}

struct proxy_state *proxy_alloc_ps()
{
	struct proxy_state *ps;

	ps = mem_alloc(sizeof(*ps));
	if (NULL == ps)
		return NULL;

	bzero(ps, sizeof(*ps));

	ps->cli_fd = -1;
	ps->svr_fd = -1;

	proxy_ref_ps(ps);

	ps->peep = m_proxy_opts.peep;
	INIT_LIST_HEAD(&ps->events);

	return ps;
}

void proxy_free_ssl_state(struct ssl_state *ss)
{
	if (ss->ssl)
		SSL_free(ss->ssl);
	if (ss->crt)
		X509_free(ss->crt);
	mem_free(ss);
}

void proxy_unref_ps(struct proxy_state *ps)
{
	ps->ref -= 1;

	log_debug("%s->%s %s->%s, ref: %d",
	          sockaddr_string(&ps->cli), sockaddr_string1(&ps->cself),
	          sockaddr_string2(&ps->sself), sockaddr_string3(&ps->svr),
	          ps->ref);

	if (0 < ps->ref)
		return;

	log_info("%s->%s %s->%s, cli_fd: %d, svr_fd: %d free state",
	         sockaddr_string(&ps->cli), sockaddr_string1(&ps->cself),
	         sockaddr_string2(&ps->sself), sockaddr_string3(&ps->svr),
	         ps->cli_fd, ps->svr_fd);

	if (ps->client)
		proxy_free_ssl_state(ps->client);
	if (ps->cli_fd >= 0)
		close(ps->cli_fd);

	if (ps->server)
		proxy_free_ssl_state(ps->server);
	if (ps->svr_fd >= 0)
		close(ps->svr_fd);

	mem_free(ps);

}

void proxy_free_event(struct proxy_event *pe)
{
	log_debug("%s->%s %s->%s free event %s",
	          sockaddr_string(&pe->ps->cli),
	          sockaddr_string1(&pe->ps->cself),
	          sockaddr_string2(&pe->ps->sself),
	          sockaddr_string3(&pe->ps->svr),
	          pe->what);

	proxy_unref_ps(pe->ps);

	list_del(&pe->node);

	mem_free(pe);
}

void proxy_free_ps(struct proxy_state *ps)
{
	struct proxy_event *pe;
	struct proxy_event *tmp;

	list_for_each_entry_safe(pe, tmp, &ps->events, node) {
		if (pe->e) {
			log_info("cancel %s, event: %s %d %d", pe->what,
			         pe->e->name, pe->e->type, pe->e->fd);

			event_cancel_event(pe->e);
		}
		if (pe->async && pe->async_other) {
			log_info("cancel %s, event: %s %d %d", pe->what,
			         pe->async_other->name,
			         pe->async_other->type,
			         pe->async_other->fd);

			event_cancel_event(pe->async_other);
		}
		proxy_free_event(pe);
	}

	proxy_unref_ps(ps);
}

struct proxy_event *proxy_get_event(
	struct proxy_state *ps,
	int (*handler)(struct proxy_state *),
	const char *what)
{
	struct proxy_event *pe;

	pe = mem_alloc(sizeof(*pe));
	if (NULL == pe)
		return NULL;

	pe->ps = ps;
	pe->handler = handler;
	pe->e = NULL;
	pe->what = what;
	pe->async = 0;
	pe->async_other = NULL;
	list_add(&pe->node, &ps->events);
	proxy_ref_ps(ps);

	return pe;
}

int proxy_event_handler(struct event *e)
{
	struct proxy_event *pe;
	struct proxy_state *ps;
	int (*handler)(struct proxy_state *);
	int ret;

	pe = e->arg;
	handler = pe->handler;
	ps = pe->ps;

	log_info("%s->%s %s->%s fd %d run %s",
	         sockaddr_string(&ps->cli), sockaddr_string1(&ps->cself),
	         sockaddr_string2(&ps->sself), sockaddr_string3(&ps->svr),
	         e->fd, pe->what);
	if (pe->async) {
		if (e->type == EVENT_READ && pe->async_other) {
			event_cancel_event(pe->async_other);
			pe->async_other = NULL;
		} else if (e->type == EVENT_WRITE && pe->e) {
			event_cancel_event(pe->e);
			pe->e = NULL;
		}
	}
	proxy_free_event(pe);

	ret = handler(ps);

	return ret;
}

int proxy_add_read(
	struct proxy_state *ps,
	int fd,
	enum ssl_dir dir,
	int (*handler)(struct proxy_state *),
	const char *what)
{
	struct proxy_event *pe;
	struct event_scheduler *es;

	if (dir == SSL_DIR_2C)
		ps->cli_active = g_proxy_time;
	else
		ps->svr_active = g_proxy_time;

	pe = proxy_get_event(ps, handler, what);
	if (NULL == pe) {
		proxy_error(ps, dir, "fail to get event when add read %s on %d",
		            what, fd);

		proxy_free_ps(ps);

		return -1;
	}

	pe->async = 0;
	pe->async_other = NULL;
	es = proxy_get_event_scheduler();
	pe->e = event_add_read(es, proxy_event_handler, pe, fd);
	if (NULL == pe->e) {
		proxy_error(ps, dir, "fail to add read %s on %d", what, fd);

		proxy_free_ps(ps);

		return -1;
	}

	proxy_info(ps, dir, "add read %s on %d", what, fd);

	return 0;
}

int proxy_add_write(
	struct proxy_state *ps,
	int fd,
	enum ssl_dir dir,
	int (*handler)(struct proxy_state *),
	const char *what)
{
	struct proxy_event *pe;
	struct event_scheduler *es;

	if (dir == SSL_DIR_2C)
		ps->cli_active = g_proxy_time;
	else
		ps->svr_active = g_proxy_time;

	pe = proxy_get_event(ps, handler, what);
	if (NULL == pe) {
		proxy_log(ps, dir, LOG_LV_ERROR,
		          "fail to get event when add write %s on %d",
		          what, fd);

		proxy_free_ps(ps);

		return -1;
	}

	pe->async = 0;
	pe->async_other = NULL;
	es = proxy_get_event_scheduler();
	pe->e = event_add_write(es, proxy_event_handler, pe, fd);
	if (NULL == pe->e) {
		proxy_log(ps, dir, LOG_LV_ERROR,
		          "fail to add write %s on %d",
		          what, fd);

		proxy_free_ps(ps);

		return -1;
	}

	proxy_log(ps, dir, LOG_LV_DEBUG, "add write %s on %d", what, fd);

	return 0;
}

int proxy_process_async(
	struct proxy_state *ps,
	enum ssl_dir dir,
	int (*handler)(struct proxy_state *),
	const char *what)
{
	OSSL_ASYNC_FD *add_fds;
	size_t nr_add;
	struct ssl_state *ss;
	size_t i;
	struct proxy_event *pe;
	struct event_scheduler *es;

	if (dir == SSL_DIR_2C)
		ps->cli_active = g_proxy_time;
	else
		ps->svr_active = g_proxy_time;

	proxy_debug(ps, dir, "proxy_process_async");

	add_fds = NULL;

	ss = SSL_DIR_2C == dir ? ps->client : ps->server;
	SSL_get_all_async_fds(ss->ssl, NULL, &nr_add);
	if (0 == nr_add)
		return 0;

	add_fds = mem_alloc(nr_add * sizeof(OSSL_ASYNC_FD));
	if (NULL == add_fds) {
		proxy_error(ps, dir, "no memory, add async");
		proxy_free_ps(ps);

		return -1;
	}
	SSL_get_all_async_fds(ss->ssl, add_fds, &nr_add);

	for (i = 0; i < nr_add; i++) {
		pe = proxy_get_event(ps, handler, what);
		if (NULL == pe) {
			proxy_error(ps, dir,
			            "fail to get event when add async %s",
			            what);

			mem_free(add_fds);
			proxy_free_ps(ps);

			return -1;
		}

		pe->async = 1;
		es = proxy_get_event_scheduler();
		pe->e = event_add_read(es, proxy_event_handler, pe, add_fds[i]);
		if (NULL == pe->e) {
			proxy_error(ps, dir, "fail to add read %s on %d",
			            what, add_fds[i]);

			mem_free(add_fds);
			proxy_free_ps(ps);

			return -1;
		}
		pe->async_other = event_add_write(es, proxy_event_handler,
		                                  pe, add_fds[i]);
		if (NULL == pe->e) {
			proxy_error(ps, dir, "fail to add read %s on %d",
			            what, add_fds[i]);

			mem_free(add_fds);
			proxy_free_ps(ps);

			return -1;
		}

		proxy_info(ps, dir, "add sync %s on %d", what, add_fds[i]);
	}
	mem_free(add_fds);

	return 0;
}

int proxy_add_timeout(
	struct proxy_state *ps,
	int sec,
	enum ssl_dir dir,
	int (*handler)(struct proxy_state *),
	const char *what)
{
	struct proxy_event *pe;
	struct event_scheduler *es;

	pe = proxy_get_event(ps, handler, what);
	if (NULL == pe) {
		proxy_log(ps, dir, LOG_LV_ERROR,
		          "fail to get event when add timer %s after %d s",
		          what, sec);

		proxy_free_ps(ps);

		return -1;
	}

	es = proxy_get_event_scheduler();
	pe->e = event_add_timer(es, proxy_event_handler, pe, sec);
	if (NULL == pe->e) {
		proxy_log(ps, dir, LOG_LV_ERROR,
		          "fail to add timer %s after %d s",
		          what, sec);

		proxy_free_ps(ps);

		return -1;
	}

	proxy_log(ps, dir, LOG_LV_DEBUG, "add timer %s after %d s", what, sec);

	return 0;
}

void proxy_ssl_trace_cb(const SSL *ssl, int where, int ret)
{
	log_debug("error");
	if (where & SSL_CB_EXIT) {
		log_debug("error");
	}
}

int proxy_timeout(struct proxy_state *ps)
{
	if (g_proxy_time - ps->svr_active > PROXY_TIMEOUT
	    || g_proxy_time - ps->cli_active > PROXY_TIMEOUT) {
		proxy_free_ps(ps);

		return 0;
	}

	if (0 != proxy_add_timeout(ps, PROXY_TIMEOUT, SSL_DIR_2C,
	                           proxy_timeout, "timeout")) {
		proxy_free_ps(ps);

		return -1;
	}

	return 0;
}

int proxy_init_self_ssl_ctx(char *key_file, char *csr_file, int type)
{
	SSL_CTX *ctx;
	long ssloptions =
		SSL_OP_ALL | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
		| SSL_OP_NO_COMPRESSION;
	BIO *ssl_bio;
	BIO *in_bio;
	BIO *out_bio;

	ctx = SSL_CTX_new(SSLv23_server_method());
	if (ctx == NULL) {
		log_fatal("SSL_CTX_new, err: %s", PROXY_SSL_ERROR);

		return -1;
	}

	SSL_CTX_set_options(ctx, ssloptions);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);

	/* 载入用户私钥 */
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, type) <= 0) {
		log_fatal("SSL_CTX_use_PrivateKey_file err : %s",
		          PROXY_SSL_ERROR);
		SSL_CTX_free(ctx);

		return -1;
	}

	/* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
	if (SSL_CTX_use_certificate_file(ctx, csr_file, type) <= 0) {
		log_fatal("SSL_CTX_use_certificate_file err : %s",
		          PROXY_SSL_ERROR);
		SSL_CTX_free(ctx);
		return -1;
	}

	/* 检查用户私钥是否正确 */
	if (!SSL_CTX_check_private_key(ctx)) {
		log_fatal("SSL_CTX_check_private_key err : %s",
		          PROXY_SSL_ERROR);
		SSL_CTX_free(ctx);

		return -1;
	}

	/* set our supported ciphers */
	if (1 != SSL_CTX_set_cipher_list(
		ctx,
		"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
		"ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:!RC4")) {
		log_error("SSL_CTX_set_cipher_list err : %s",
		          ERR_error_string(ERR_get_error(), NULL));
		SSL_CTX_free(ctx);

		return -1;
	}
	SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	//SSL_CTX_set_ecdh_auto(ctx, 1);
	//SSL_CTX_set_default_read_ahead(ctx, 1);
	SSL_CTX_set_mode(ctx, SSL_CTX_get_mode(ctx)
	                      | SSL_MODE_ENABLE_PARTIAL_WRITE
	                      | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
	                      | SSL_MODE_RELEASE_BUFFERS);

	self_ssl_ctx = ctx;

	m_peek_sni_ssl = SSL_new(self_ssl_ctx);
	if (NULL == m_peek_sni_ssl) {
		log_fatal("fail to new ssl to peek sni, %s",
		          PROXY_SSL_ERROR);
		SSL_CTX_free(self_ssl_ctx);

		return -1;
	}

	ssl_bio = BIO_new(BIO_f_ssl());
	// TODO

	in_bio = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(in_bio, -1);
	m_peek_sni_ssl_in_bio = in_bio;

	out_bio = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(out_bio, -1);
	SSL_set_bio(m_peek_sni_ssl, in_bio, out_bio);
	BIO_set_ssl(ssl_bio, m_peek_sni_ssl, BIO_NOCLOSE);
	SSL_set_accept_state(m_peek_sni_ssl);

	log_info("proxy ssl init ok");
	return 0;
}

int proxy_init_opts()
{
	struct proxy_opts *opts;
	SSL_CTX *ctx;
	SSL *ssl;
	RSA *rsa;

	opts = &m_proxy_opts;

	opts->chain = sk_X509_new_null();

	rsa = RSA_generate_key(2048, 3, NULL, NULL);
	if (NULL == rsa) {
		log_fatal("fail to generate rsa key");

		return -1;
	}
	opts->key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(opts->key, rsa);

	ctx = SSL_CTX_new(SSLv23_server_method());
	if (NULL == ctx) {
		log_fatal("fail to new ssl ctx %s", PROXY_SSL_ERROR);

		return -1;
	}

	if (1 != SSL_CTX_use_PrivateKey_file(ctx, PROXY_CA_KEY_PATH,
	                                     SSL_FILETYPE_PEM)) {
		log_fatal("fail to use private key file %s, %s",
		          PROXY_CA_KEY_PATH, PROXY_SSL_ERROR);

		SSL_CTX_free(ctx);

		return -1;
	}

	if (1 != SSL_CTX_use_certificate_file(ctx, PROXY_CA_CERT_PATH,
	                                      SSL_FILETYPE_PEM)) {
		log_fatal("fail to use private cert file %s, %s",
		          PROXY_CA_CERT_PATH, PROXY_SSL_ERROR);

		SSL_CTX_free(ctx);

		return -1;
	}

	ssl = SSL_new(ctx);
	if (NULL == ssl) {
		log_fatal("fail to create ssl object, %s", PROXY_SSL_ERROR);
		SSL_CTX_free(ctx);

		return -1;
	}

	opts->cakey = SSL_get_privatekey(ssl);
	opts->cacrt = SSL_get_certificate(ssl);

	EVP_PKEY_up_ref(opts->cakey);
	X509_up_ref(opts->cacrt);

	sk_X509_insert(opts->chain, opts->cacrt, 0);

	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}

/*
 * Copy the serial number from cli certificate to svr certificate
 * and modify it by a random offset.
 * If reading the serial fails for some reason, generate a new
 * random serial and store it in the svr certificate.
 * Using the same serial is not a good idea since some SSL stacks
 * check for duplicate certificate serials.
 * Returns 0 on success, -1 on error.
 */
int proxy_copyrand(X509 *dstcrt, X509 *srccrt)
{
	ASN1_INTEGER *srcptr, *dstptr;
	BIGNUM *bnserial;
	unsigned int rand;
	int rv;

	rv = RAND_pseudo_bytes((unsigned char *) &rand, sizeof(rand));

	dstptr = X509_get_serialNumber(dstcrt);/* 获取证书序列号 */
	srcptr = X509_get_serialNumber(srccrt);
	if ((rv == -1) || !dstptr || !srcptr)
		return -1;
	bnserial = ASN1_INTEGER_to_BN(srcptr, NULL);
	if (!bnserial) {
		/* random 32-bit serial */
		ASN1_INTEGER_set(dstptr, rand);
	} else {
		/* original serial plus random 32-bit offset */
		BN_add_word(bnserial, rand);
		BN_to_ASN1_INTEGER(bnserial, dstptr);
		BN_free(bnserial);
	}
	return 0;
}

int proxy_copy_create_time(X509 *crt, X509 *cacrt)
{
	void *begin_dup;
	void *end_dup;
	int ret;

	begin_dup = ASN1_STRING_dup(X509_get_notBefore(cacrt));
	end_dup = ASN1_STRING_dup(X509_get_notAfter(cacrt));

	if (begin_dup && end_dup) {
		X509_set_notBefore(crt, begin_dup);
		X509_set_notAfter(crt, end_dup);

		ret = 0;
	} else {
		ret = -1;
	}

	if (begin_dup)
		ASN1_STRING_free(begin_dup);

	if (end_dup)
		ASN1_STRING_free(end_dup);

	return ret;
}

/*
 * Add a X509v3 extension to a certificate and handle errors.
 * Returns -1 on errors, 0 on success.
 */
int
proxy_add_x509_v3ext(X509V3_CTX *ctx, X509 *crt, char *k, char *v)
{
	X509_EXTENSION *ext;

	if (!(ext = X509V3_EXT_conf(NULL, ctx, k, v))) {
		return -1;
	}
	if (X509_add_ext(crt, ext, -1) != 1) {
		X509_EXTENSION_free(ext);
		return -1;
	}
	X509_EXTENSION_free(ext);
	return 0;
}

int
proxy_ssl_x509_v3ext_copy_by_nid(X509 *crt, X509 *origcrt, int nid)
{
	X509_EXTENSION *ext;
	int pos;

	pos = X509_get_ext_by_NID(origcrt, nid, -1);
	if (pos == -1)
		return 0;
	ext = X509_get_ext(origcrt, pos);
	if (!ext)
		return -1;
	if (X509_add_ext(crt, ext, -1) != 1)
		return -1;
	return 1;
}

X509 *proxy_make_cert(X509 *cacrt, EVP_PKEY *cakey, X509 *svr_crt,
                      const char *extraname, EVP_PKEY *key)
{
	X509_NAME *subject, *issuer;
	GENERAL_NAMES *names;
	GENERAL_NAME *gn;
	X509 *crt;

	if (!cacrt || !cakey || !key) {
		log_error("cacrt %p, cakey %p, key %p");
		return NULL;
	}

	/* 获取证书拥有者 */
	subject = X509_get_subject_name(svr_crt);
	issuer = X509_get_subject_name(cacrt);
	if (!subject || !issuer) {
		log_error("subject %p, issuer %p", subject, issuer);

		return NULL;
	}

	crt = X509_new();
	if (!crt) {
		log_error("X509_new error when make cert");

		return NULL;
	}

	if (!X509_set_version(crt, 0x02) ||
	    !X509_set_subject_name(crt, subject) || /* 设置证书主体名 */
	    !X509_set_issuer_name(crt, issuer) || /* 设置证书签发者 */
	    proxy_copyrand(crt, svr_crt) == -1 ||
	    /*
	    !X509_gmtime_adj(X509_get_notBefore(crt), (long)-60*60*24) ||
	    !X509_gmtime_adj(X509_get_notAfter(crt), (long)60*60*24*364) ||*/

	    !X509_set_pubkey(crt, key))
		goto errout;

	if (proxy_copy_create_time(crt, cacrt))
		goto errout;

	/* add standard v3 extensions; cf. RFC 2459 */
	X509V3_CTX ctx;
	X509V3_set_ctx(&ctx, cacrt, crt, NULL, NULL, 0);
	if (proxy_add_x509_v3ext(&ctx, crt, "basicConstraints",
	                         "CA:FALSE") == -1 ||
	    proxy_add_x509_v3ext(&ctx, crt, "keyUsage",
	                         "digitalSignature,"
	                         "keyEncipherment") == -1 ||
	    proxy_add_x509_v3ext(&ctx, crt, "extendedKeyUsage",
	                         "serverAuth") == -1 ||
	    proxy_add_x509_v3ext(&ctx, crt, "subjectKeyIdentifier",
	                         "hash") == -1 ||
	    proxy_add_x509_v3ext(&ctx, crt, "authorityKeyIdentifier",
	                         "keyid,issuer:always") == -1)
		goto errout;

	if (!extraname) {
		/* no extraname provided: copy original subjectAltName ext */
		if (proxy_ssl_x509_v3ext_copy_by_nid(crt, svr_crt,
		                                     NID_subject_alt_name) ==
		    -1)
			goto errout;
	} else {
		names = X509_get_ext_d2i(svr_crt, NID_subject_alt_name, 0, 0);
		if (!names) {
			/* no subjectAltName present: add new one */
			char cfval[HOST_STR_LEN];
			if (snprintf(cfval, sizeof(cfval), "DNS:%s",
			             extraname) < 0)
				goto errout;
			if (proxy_add_x509_v3ext(&ctx, crt, "subjectAltName",
			                         cfval) == -1) {
				goto errout;
			}
		} else {
			/* add extraname to original subjectAltName
			 * and add it to the new certificate */
			gn = GENERAL_NAME_new();
			if (!gn)
				goto errout2;
			gn->type = GEN_DNS;
			gn->d.dNSName = ASN1_STRING_type_new(V_ASN1_IA5STRING);
			if (!gn->d.dNSName)
				goto errout3;
			ASN1_STRING_set(gn->d.dNSName,
			                (unsigned char *) extraname,
			                (int) strlen(extraname));
			sk_GENERAL_NAME_push(names, gn);
			X509_EXTENSION *ext = X509V3_EXT_i2d(
				NID_subject_alt_name, 0, names);
			if (!X509_add_ext(crt, ext, -1)) {
				if (ext) {
					X509_EXTENSION_free(ext);
				}
				goto errout2;
			}
			X509_EXTENSION_free(ext);
			sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
		}
	}

	const EVP_MD *md;
	switch (EVP_PKEY_type(EVP_PKEY_get_id(cakey))) {
	case EVP_PKEY_RSA:
		switch (X509_get_signature_nid(svr_crt)) {
		case NID_md5WithRSAEncryption:
			md = EVP_md5();
			break;
		case NID_sha224WithRSAEncryption:
			md = EVP_sha224();
			break;
		case NID_sha256WithRSAEncryption:
			md = EVP_sha256();
			break;
		case NID_sha384WithRSAEncryption:
			md = EVP_sha384();
			break;
		case NID_sha512WithRSAEncryption:
			md = EVP_sha512();
			break;
		case NID_shaWithRSAEncryption:
		case NID_sha1WithRSAEncryption:
		default:
			md = EVP_sha256();
			break;
		}
		break;
	case EVP_PKEY_DSA:
		md = EVP_sha1();
		break;
	case EVP_PKEY_EC:
		md = EVP_sha256();
		break;
	default:
		goto errout;
	}

	if (!X509_sign(crt, cakey, md))
		goto errout;

	return crt;

errout3:
	GENERAL_NAME_free(gn);
errout2:
	sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
errout:
	X509_free(crt);
	return NULL;
}

static void proxy_set_ctx_options(SSL_CTX *sslctx)
{
	SSL_CTX_set_options(sslctx, SSL_OP_ALL);
#ifdef SSL_OP_TLS_ROLLBACK_BUG
	SSL_CTX_set_options(sslctx, SSL_OP_TLS_ROLLBACK_BUG);
#endif /* SSL_OP_TLS_ROLLBACK_BUG */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
	SSL_CTX_set_options(sslctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif /* SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
	SSL_CTX_set_options(sslctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif /* SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_TICKET
	SSL_CTX_set_options(sslctx, SSL_OP_NO_TICKET);
#endif /* SSL_OP_NO_TICKET */

	/*
	 * Do not use HAVE_SSLV2 because we need to set SSL_OP_NO_SSLv2 if it
	 * is available and WITH_SSLV2 was not used.
	 */
#ifdef SSL_OP_NO_SSLv2
	SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2);
#endif /* !SSL_OP_NO_SSLv2 */
#ifdef SSL_OP_NO_SSLv3
	SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv3);
#endif /* !SSL_OP_NO_SSLv3 */
#ifdef SSL_OP_NO_TLSv1
	SSL_CTX_set_options(sslctx, SSL_OP_NO_TLSv1);
#endif /* !SSL_OP_NO_TLSv1 */
	SSL_CTX_set_options(sslctx, SSL_OP_NO_ENCRYPT_THEN_MAC);

	SSL_CTX_set_cipher_list(
		sslctx,
		"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
		"ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:AES256-SHA256:"
		"!RC4");
}

struct ssl_state *proxy_create_cli_ssl_state(struct proxy_state *ps)
{
	int i;
	struct ssl_state *ss;

	ss = mem_alloc(sizeof(*ss));
	if (NULL == ss) {
		log_error("fail to alloc client ssl state");

		return NULL;
	}
	bzero(ss, sizeof(*ss));
	ps->client = ss;

	ss->crt = proxy_make_cert(m_proxy_opts.cacrt, m_proxy_opts.cakey,
	                          ps->server->crt, NULL, m_proxy_opts.key);
	if (NULL == ss->crt) {
		log_error("fail to make cert");

		return NULL;
	}

	ss->ctx = SSL_CTX_new(SSLv23_method());
	proxy_set_ctx_options(ss->ctx);

	SSL_CTX_use_certificate(ss->ctx, ss->crt);
	SSL_CTX_use_PrivateKey(ss->ctx, m_proxy_opts.key);
	for (i = 0; i < sk_X509_num(m_proxy_opts.chain); i++) {
		X509 *c = sk_X509_value(m_proxy_opts.chain, i);

		SSL_CTX_add_extra_chain_cert(ss->ctx, c);
	}
	SSL_CTX_set_timeout(ss->ctx, 120);

	ss->ssl = SSL_new(ss->ctx);
	if (NULL == ss->ssl) {
		log_error("SSL_new err : %s", PROXY_SSL_ERROR);
		mem_free(ss);

		return NULL;
	}

	SSL_set_info_callback(ss->ssl, proxy_ssl_trace_cb);

#ifdef SSL_MODE_RELEASE_BUFFERS
	/* lower memory footprint for idle connections */
	SSL_set_mode(ss->ssl,
	             SSL_get_mode(ss->ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */
	if (m_proxy_opts.async)
		SSL_set_mode(ss->ssl, SSL_MODE_ASYNC);

	SSL_set_app_data(ss->ssl, ps);

	ss->ssl_bio = BIO_new(BIO_f_ssl());
	if (!ss->ssl_bio) {
		log_error("cannot allocate ssl bio : %s", PROXY_SSL_ERROR);
		SSL_free(ss->ssl);
		mem_free(ss);

		return NULL;
	}

	ss->in_bio = BIO_new(BIO_s_mem());
	if (!ss->in_bio) {
		log_error("cannot allocate read bio : %s", PROXY_SSL_ERROR);
		BIO_free(ss->ssl_bio);
		SSL_free(ss->ssl);
		mem_free(ss);

		return NULL;
	}
	BIO_set_mem_eof_return(ss->in_bio, -1);

	ss->out_bio = BIO_new(BIO_s_mem());
	if (!ss->out_bio) {
		log_error("cannot allocate write bio : %s", PROXY_SSL_ERROR);
		BIO_free(ss->ssl_bio);
		BIO_free(ss->in_bio);
		SSL_free(ss->ssl);
		mem_free(ss);

		return NULL;
	}
	BIO_set_mem_eof_return(ss->out_bio, -1);

	SSL_set_bio(ss->ssl, ss->in_bio, ss->out_bio);
	BIO_set_ssl(ss->ssl_bio, ss->ssl, BIO_NOCLOSE);
	SSL_set_accept_state(ss->ssl);

	ss->want = SSL_WANT_READ;
	ss->dir = SSL_DIR_2C;
	ss->need_finish = 0;
	ss->handshaked = 0;

	return ss;
}

struct ssl_state *proxy_create_svr_ssl_state(const char *sni)
{
	struct ssl_state *ss;

	ss = mem_alloc(sizeof(*ss));
	if (NULL == ss) {
		log_error("fail to alloc server ssl state");

		return NULL;
	}

	ss->ctx = SSL_CTX_new(SSLv23_client_method());
	if (NULL == ss->ctx) {
		log_error("SSL_CTX_new err : %s", PROXY_SSL_ERROR);
		mem_free(ss);

		return NULL;
	}
	proxy_set_ctx_options(ss->ctx);
	SSL_CTX_set_verify(ss->ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_timeout(ss->ctx, 120);

	ss->ssl = SSL_new(ss->ctx);
	SSL_CTX_free(ss->ctx);
	if (NULL == ss->ssl) {
		log_error("SSL_new error:%s ", PROXY_SSL_ERROR);
		mem_free(ss);

		return NULL;
	}
#ifndef OPENSSL_NO_TLSEXT
	if (sni) {
		SSL_set_tlsext_host_name(ss->ssl, sni);
	}
#endif /* !OPENSSL_NO_TLSEXT */
#ifdef SSL_MODE_RELEASE_BUFFERS
	/* lower memory footprint for idle connections */
	SSL_set_mode(ss->ssl, SSL_get_mode(ss->ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */

	if (m_proxy_opts.async)
		SSL_set_mode(ss->ssl, SSL_MODE_ASYNC);

	ss->ssl_bio = BIO_new(BIO_f_ssl());
	if (!ss->ssl_bio) {
		log_error("cannot allocate ssl bio : %s\n", PROXY_SSL_ERROR);
		SSL_free(ss->ssl);
		mem_free(ss);

		return NULL;
	}
	//BIO_set_mem_eof_return(ssl_state->ssl_bio, -1);

	ss->in_bio = BIO_new(BIO_s_mem());
	if (!ss->in_bio) {
		log_error("cannot allocate read bio : %s\n", PROXY_SSL_ERROR);
		BIO_free(ss->ssl_bio);
		SSL_free(ss->ssl);
		mem_free(ss);
		return NULL;
	}
	BIO_set_mem_eof_return(ss->in_bio, -1);

	ss->out_bio = BIO_new(BIO_s_mem());
	if (!ss->out_bio) {
		log_error("cannot allocate write bio : %s\n", PROXY_SSL_ERROR);
		BIO_free(ss->ssl_bio);
		BIO_free(ss->in_bio);
		SSL_free(ss->ssl);
		mem_free(ss);
		return NULL;
	}
	BIO_set_mem_eof_return(ss->out_bio, -1);

	SSL_set_bio(ss->ssl, ss->in_bio, ss->out_bio);
	BIO_set_ssl(ss->ssl_bio, ss->ssl, BIO_NOCLOSE);
	SSL_set_connect_state(ss->ssl);

	ss->want = SSL_WANT_WRITE;
	ss->dir = SSL_DIR_2S;
	ss->need_finish = 0;
	ss->handshaked = 0;

	return ss;
}

int proxy_bio_2_tcp(
	BIO *bio,
	int fd,
	struct proxy_state *ps,
	struct ssl_state *ss)
{
	char buf[PROXY_SEND_BUF];
	ssize_t len;
	ssize_t wlen;

	while (BIO_ctrl_pending(bio)) {
		len = BIO_read(bio, buf, sizeof(buf));
		wlen = write(fd, buf, len);

		log_debug("%s->%s %s->%s write len %d, wlen %d, fd %d",
		          sockaddr_string(&ps->cli),
		          sockaddr_string1(&ps->cself),
		          sockaddr_string1(&ps->sself),
		          sockaddr_string2(&ps->svr),
		          len, wlen, fd);

		if (wlen <= 0) {
			ss->need_finish = 1;

			return -1;
		}

		// TODO 这里应该有个send buf，wlen -> len 的数据已经从bio读出来了
		if (wlen < len) {
			ss->want = SSL_WANT_WRITE;

			return 0;
		}
	}

	ss->want = SSL_WANT_READ;

	return 0;
}

int proxy_handshake_write(
	int fd,
	struct proxy_state *ps,
	struct ssl_state *ss)
{
	return proxy_bio_2_tcp(ss->out_bio, fd, ps, ss);
}

int proxy_read(int fd, char *buf, int buf_len)
{
	ssize_t rlen;

	rlen = read(fd, buf, buf_len);
	if (0 == rlen) {
		log_info("close when read, fd: %d", fd);

		return 0;
	} else if (rlen < 0) {
		log_error("read error, fd: %d", fd);

		return (int) rlen;
	}

	return (int) rlen;
}

int proxy_tcp_2_bio(int fd,
                    BIO *bio,
                    struct proxy_state *ps,
                    struct ssl_state *ss)
{
	char buf[RECV_BUF_LEN];
	ssize_t rlen;
	ssize_t wlen;

	rlen = proxy_read(fd, buf, sizeof(buf));
	if (rlen <= 0) {
		proxy_info(ps, ss->dir, "need finish after read.");

		ss->need_finish = 1;

		return -1;
	}

	wlen = BIO_write(bio, buf, (int) rlen);
	proxy_debug(ps, ss->dir, "tcp to bio, rlen: %d, wlen: %d", rlen, wlen);
	/* TODO 判断是不是都写进去了 */

	return 0;
}

void proxy_process_ssl_error(
	int ssl_ret,
	struct proxy_state *ps,
	struct ssl_state *ss)
{
	switch (SSL_get_error(ss->ssl, ssl_ret)) {
	case SSL_ERROR_WANT_READ:
		// 两种情况：
		// 1. openssl处理完了对端的输入，把要响应的报文写到了out_bio，它想要
		//    读对端看到out_bio中的内容的响应
		// 2. openssl读in_bio的时候发现需要的报文还没有收全，得等收全了再处理
		//    比如证书只传了一半。
		if (BIO_ctrl_pending(ss->out_bio))
			ss->want = SSL_WANT_WRITE;
		else
			ss->want = SSL_WANT_READ;

		proxy_info(ps, ss->dir, "ssl error want read, want %d",
		           ss->want);

		break;
	case SSL_ERROR_WANT_WRITE:
		// 一般应该不会出现这种情况，因为out_bio是BIO_s_mem，可以直接写入，除
		// 非写满了的情况
		ss->want = SSL_WANT_WRITE;

		proxy_info(ps, ss->dir, "ssl error want write, want %d",
		           ss->want);

		break;
	case SSL_ERROR_WANT_ASYNC:
		ss->want = SSL_WANT_ASYNC;

		proxy_info(ps, ss->dir, "ssl error want async, want %d",
		           ss->want);

		break;
	default:
		proxy_error(ps, ss->dir, "ssl error: %d %s",
		            ERR_get_error(), PROXY_SSL_ERROR);
		ss->need_finish = 1;
		break;
	}
}

int proxy_handshake_read(
	int fd,
	struct proxy_state *ps,
	struct ssl_state *ss)
{
	int ret;

	ret = proxy_tcp_2_bio(fd, ss->in_bio, ps, ss);
	if (ss->need_finish)
		return ret;

	ret = SSL_do_handshake(ss->ssl);
	if (1 == ret) {
		proxy_info(ps, ss->dir, "handshake ok.");

		ss->handshaked = 1;

		return 0;
	}
	proxy_process_ssl_error(ret, ps, ss);

	proxy_info(ps, ss->dir, "want: %d.", ss->want);

	return 0;
}

int proxy_connect(struct sockaddr *addr, socklen_t len, int *again)
{
	int fd;

	fd = get_none_block_tcp_connect_socket(addr->sa_family);
	if (fd <= 0)
		return -1;

	if (0 == connect(fd, addr, len))
		return fd;

	if (EAGAIN != errno && EINPROGRESS != errno) {
		close(fd);

		*again = 0;

		return -1;
	}

	*again = 1;

	return fd;
}

int proxy_start_handshake_client(struct proxy_state *ps)
{
	proxy_info(ps, SSL_DIR_2C, "start handshake client");

	ps->server->crt = SSL_get_peer_certificate(ps->server->ssl);
	if (NULL == ps->server->crt) {
		proxy_error(ps, SSL_DIR_2S, "server has no cert");

		return -1;
	}

	ps->client = proxy_create_cli_ssl_state(ps);
	if (NULL == ps->client) {
		proxy_error(ps, SSL_DIR_2C, "fail to create server ssl state");

		return -1;
	}

	proxy_handshake_read(ps->cli_fd, ps, ps->client);

	return 0;
}

int proxy_wait_cli_req(struct proxy_state *ps);

int proxy_wait_server_response(struct proxy_state *ps)
{
	struct ssl_state *ss;
	int ret;
	char buf[RECV_BUF_LEN];
	int rlen;
	int wlen;

	if (0 != proxy_add_read(ps, ps->svr_fd, SSL_DIR_2S,
	                        proxy_wait_server_response,
	                        "wait_server_response")) {
		ret = -1;
		goto ERROR;
	}

	ss = ps->server;
	ret = proxy_tcp_2_bio(ps->svr_fd, ss->in_bio, ps, ss);
	if (ss->need_finish) {
		proxy_free_ps(ps);

		goto ERROR;
	}

	while (BIO_ctrl_pending(ss->ssl_bio)) {
		rlen = BIO_read(ss->ssl_bio, buf, sizeof(buf));
		buf[rlen] = '\0';
		log_debug("receive %.*s, rlen: %d", rlen, buf, rlen);
		wlen = BIO_write(ps->client->ssl_bio, buf, rlen);
		if (wlen < rlen) {
			// TODO
		}
		proxy_bio_2_tcp(ps->client->out_bio, ps->cli_fd, ps,
		                ps->client);
	}

	return 0;
ERROR:

	return ret;

}

int proxy_cli_plain_2_svr(struct proxy_state *ps)
{
	char buf[RECV_BUF_LEN];
	int rlen;
	int wlen;
	struct ssl_state *cli;
	struct ssl_state *svr;

	cli = ps->client;
	svr = ps->server;

	rlen = BIO_read(cli->ssl_bio, buf, sizeof(buf));
	buf[rlen] = '\0';
	log_debug("receive %.*s, rlen: %d", rlen, buf, rlen);
	wlen = BIO_write(svr->ssl_bio, buf, rlen);
	if (wlen < rlen) {
		// TODO
	}

	return proxy_bio_2_tcp(svr->out_bio, ps->svr_fd, ps, svr);
}

int proxy_cli_2_svr(struct proxy_state *ps)
{
	int ret;

	ret = proxy_tcp_2_bio(ps->cli_fd, ps->client->in_bio, ps, ps->client);
	if (ps->client->need_finish)
		return ret;

	ret = proxy_cli_plain_2_svr(ps);

	return ret;
}

int proxy_wait_cli_req(struct proxy_state *ps)
{
	int ret;

	if (0 != proxy_add_read(ps, ps->cli_fd, SSL_DIR_2C,
	                        proxy_wait_cli_req,
	                        "wait_client_request")) {
		ret = -1;

		goto ERROR;
	}

	ret = proxy_cli_2_svr(ps);
	if (ps->client->need_finish || ps->server->need_finish)
		goto ERROR;

	return 0;
ERROR:
	proxy_free_ps(ps);

	return ret;
}


int proxy_handshake_async(struct proxy_state *ps, struct ssl_state *ss)
{
	int ret;

	ret = SSL_do_handshake(ss->ssl);
	if (1 == ret) {
		ss->want = SSL_ERROR_WANT_WRITE;
		ss->handshaked = 1;

		return 0;
	}
	proxy_process_ssl_error(ret, ps, ss);

	proxy_debug(ps, ss->dir, "handshake async finish");
	if (ss->need_finish)
		return -1;

	return 0;
}


int proxy_handshake_cli(struct proxy_state *ps)
{
	struct ssl_state *ss;

	ss = ps->client;
	switch (ss->want) {
	case SSL_WANT_READ:
		proxy_info_svr(ps, "proxy_handshake_cli want read");
		proxy_handshake_read(ps->cli_fd, ps, ss);

		break;
	case SSL_WANT_WRITE:
		proxy_info_svr(ps, "proxy_handshake_cli want async");
		proxy_handshake_write(ps->cli_fd, ps, ss);

		break;
	case SSL_WANT_ASYNC:
		proxy_info_svr(ps, "proxy_handshake_cli want async");
		proxy_handshake_async(ps, ss);

		break;
	default:
		break;
	}

	if (ss->need_finish) {
		proxy_info_cli(ps, "finish handshake");

		proxy_free_ps(ps);

		goto ERROR;
	} else if (ss->handshaked) {
		if (BIO_ctrl_pending(ps->client->out_bio)) {
			// TODO 这里如果没有发完，需要处理
			proxy_handshake_write(ps->cli_fd, ps, ps->client);
		}

		proxy_cli_plain_2_svr(ps);

		if (ps->client->need_finish || ps->server->need_finish)
			goto ERROR;

		ps->client->want = SSL_WANT_READ;
		if (0 != proxy_add_read(ps, ps->cli_fd, SSL_DIR_2C,
		                        proxy_wait_cli_req,
		                        "wait request")) {
			proxy_error_cli(ps, "fail to add wait req");

			goto ERROR;
		}
		ps->server->want = SSL_WANT_READ;
		if (0 != proxy_add_read(ps, ps->svr_fd, SSL_DIR_2S,
		                        proxy_wait_server_response,
		                        "wait response")) {
			proxy_error_cli(ps, "fail to add wait rsp");

			goto ERROR;
		}

		return 0;
	}

	switch (ss->want) {
	case SSL_WANT_READ:
		if (-1 == proxy_add_read(ps, ps->cli_fd, SSL_DIR_2C,
		                         proxy_handshake_cli,
		                         "proxy_handshake_cli")) {
			proxy_error_cli(ps, "fail to add handshake cli read");

			goto ERROR;
		}
		break;
	case SSL_WANT_WRITE:
		if (-1 == proxy_add_write(ps, ps->cli_fd, SSL_DIR_2C,
		                          proxy_handshake_cli,
		                          "proxy_handshake_cli")) {
			proxy_error_cli(ps, "fail to add handshake cli write");

			goto ERROR;
		}
		break;
	case SSL_WANT_ASYNC:
		if (-1 == proxy_process_async(ps, SSL_DIR_2C,
		                              proxy_handshake_cli,
		                              "proxy_handshake_cli"))
		default:
			proxy_error_cli(ps, "fail to add handshake cli write");
		// TODO 异步
		goto ERROR;
	}

	return 0;
ERROR:
	return -1;
}

int proxy_handshake_svr(struct proxy_state *ps)
{
	struct ssl_state *ss;

	ss = ps->server;

	switch (ss->want) {
	case SSL_WANT_READ:
		proxy_info_svr(ps, "proxy_handshake_svr want read");

		proxy_handshake_read(ps->svr_fd, ps, ss);

		break;
	case SSL_WANT_WRITE:
		proxy_info_svr(ps, "proxy_handshake_svr want write");
		proxy_handshake_write(ps->svr_fd, ps, ss);

		break;
	case SSL_WANT_ASYNC:
		proxy_info_svr(ps, "proxy_handshake_svr want async");
		proxy_handshake_async(ps, ss);

		break;
	default:
		proxy_error_svr(ps, "invalid want %d", ss->want);

		goto ERROR;
	}

	if (ss->need_finish) {
		proxy_info_svr(ps, "server handshake need finish");

		proxy_free_ps(ps);

		goto ERROR;
	} else if (ss->handshaked) {
		proxy_info_svr(ps, "server handshaked");

		proxy_start_handshake_client(ps);
		if (ps->client->need_finish || ps->server->need_finish) {
			proxy_info_cli(ps, "stop handshake client");
			proxy_free_ps(ps);
			goto ERROR;
		}

		switch (ps->client->want) {
		case SSL_WANT_READ:
			if (-1 == proxy_add_read(ps, ps->cli_fd, SSL_DIR_2C,
			                         proxy_handshake_cli,
			                         "handshake client")) {
				proxy_info_cli(ps, "fail to add handshake cli");

				goto ERROR;
			}
			break;
		case SSL_WANT_WRITE:
			if (-1 == proxy_add_write(ps, ps->cli_fd, SSL_DIR_2C,
			                          proxy_handshake_cli,
			                          "handshake client")) {
				proxy_info_cli(ps, "fail to add handshake cli");

				goto ERROR;
			}
			break;
		case SSL_WANT_ASYNC:
			if (-1 == proxy_process_async(
				ps, SSL_DIR_2S, proxy_handshake_cli,
				"proxy_handshake_cli")) {
				goto ERROR;
			}
			break;
		default:
			goto ERROR;
		}

		return 0;
	}

	proxy_info_svr(ps, "server handshaking");
	switch (ss->want) {
	case SSL_WANT_READ:
		if (-1 == proxy_add_read(
			ps, ps->svr_fd, SSL_DIR_2S,
			proxy_handshake_svr,
			"proxy_handshake_svr")) {
			goto ERROR;
		}
		break;
	case SSL_WANT_WRITE:
		if (-1 == proxy_add_write(
			ps, ps->svr_fd, SSL_DIR_2S,
			proxy_handshake_svr,
			"proxy_handshake_svr")) {
			goto ERROR;
		}
		break;
	case SSL_WANT_ASYNC:
		if (-1 == proxy_process_async(
			ps, SSL_DIR_2S, proxy_handshake_svr,
			"proxy_handshake_svr")) {
			goto ERROR;
		}
		break;
	default:
		proxy_free_ps(ps);

		goto ERROR;
	}

	return 0;
ERROR:
	return -1;
}

int proxy_start_handshake_server(struct proxy_state *ps)
{
	socklen_t len;
	int ret;

	len = sizeof(ps->sself);
	if (0 != getsockname(ps->svr_fd, &ps->sself, &len)) {
		proxy_error_svr(ps, "fail to get sself addr");

		return -1;
	}
	proxy_info_svr(ps, "start handshake server");

	ps->server = proxy_create_svr_ssl_state(ps->sni);
	if (NULL == ps->server) {
		proxy_error_svr(ps, "fail to create server ssl state");

		return -1;
	}

	ret = SSL_do_handshake(ps->server->ssl);
	proxy_process_ssl_error(ret, ps, ps->server);

	return 0;
}

int proxy_wait_server_connect(struct proxy_state *ps)
{
	proxy_info_svr(ps, "proxy_wait_server_connect server connected");
	if (0 != proxy_start_handshake_server(ps)) {
		proxy_error_svr(ps, "fail to handshake server");

		proxy_free_ps(ps);

		return -1;
	}

	switch (ps->server->want) {
	case SSL_WANT_ASYNC:
		return proxy_process_async(
			ps, SSL_DIR_2S, proxy_handshake_svr,
			"proxy_handshake_svr");
	case SSL_WANT_READ:
	case SSL_WANT_WRITE:
		return proxy_add_write(
			ps, ps->svr_fd, SSL_DIR_2S, proxy_handshake_svr,
			"proxy_handshake_svr");
	default:
		// TODO
		break;
	}

	return 0;
}

int proxy_send_connected(int fd)
{
	char buf[128];

	stpcpy(buf, PROXY_CONNECTED);

	// TODO 这里不太严谨，可能没有完全发送出去
	return (int) write(fd, buf, strlen(buf));
}

int proxy_peek_sni(struct proxy_state *ps)
{
	char buf[RECV_BUF_LEN];
	int rlen;

	const char *sni;
	SSL *ssl;
	int again;
	int ret;

	rlen = (int) recv(ps->cli_fd, buf, sizeof(buf), MSG_PEEK);
	if (0 == rlen) {
		proxy_info_cli(ps, "client close connect when peek sni");

		proxy_free_ps(ps);
		ret = 0;

		goto FINISH;
	} else if (rlen < 0) {
		proxy_error_cli(ps, "recv error when peek sni");

		proxy_free_ps(ps);
		ret = -1;

		goto FINISH;
	}

	// TODO async
	ssl = m_peek_sni_ssl;
	SSL_clear(ssl);
	BIO_write(m_peek_sni_ssl_in_bio, buf, rlen);
	// TODO 错误处理

	sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (sni)
		strncpy(ps->sni, sni, sizeof(ps->sni));

	proxy_info_cli(ps, "peek sni: %s", ps->sni);

	ps->svr_fd = proxy_connect(&ps->svr, sizeof(ps->svr), &again);
	if (ps->svr_fd < 0) {
		proxy_error_cli(ps, "fail to connect, errno %d", errno);

		proxy_free_ps(ps);
		ret = -1;

		goto FINISH;
	}

	if (again) {
		proxy_info_cli(ps, "connecting server");

		if (0 != proxy_add_write(ps, ps->svr_fd, SSL_DIR_2S,
		                         proxy_wait_server_connect,
		                         "proxy_wati_server_connect")) {
			ret = -1;

			goto FINISH;
		}

		return 0;
	}

	proxy_info_cli(ps, "server connected");
	if (0 != proxy_start_handshake_server(ps)) {
		proxy_error_svr(ps, "fail to start handshake server");

		proxy_free_ps(ps);
		ret = -1;

		goto FINISH;
	}

	switch (ps->server->want) {
	case SSL_WANT_READ:
		if (0 != proxy_add_read(ps, ps->svr_fd, SSL_DIR_2S,
		                        proxy_handshake_svr,
		                        "handshake_server_read")) {
			ret = -1;
			goto FINISH;
		}

		break;
	case SSL_WANT_WRITE:
		if (0 != proxy_add_write(ps, ps->svr_fd, SSL_DIR_2S,
		                         proxy_handshake_svr,
		                         "handshake_server_write")) {
			ret = -1;
			goto FINISH;
		}

		break;
	case SSL_WANT_ASYNC:
		return proxy_process_async(
			ps, SSL_DIR_2S, proxy_handshake_svr,
			"proxy_handshake_svr");

		// TODO
	default:
		ret = -1;
		goto FINISH;
	}

	return 0;
FINISH:
	return ret;
}

int proxy_parse_connect_request(
	const char *req,
	int len,
	struct proxy_state *ps)
{
	int l;
	char stop_char;
	int offset;
	be16 port;
	struct addrinfo hints;
	struct addrinfo *result;
	int ret;

	req += sizeof(PROXY_CONNECT_REQUEST_PREFIX) - 1;
	offset = sizeof(PROXY_CONNECT_REQUEST_PREFIX) - 1;
	while (' ' == *req && offset < len) {
		req += 1;
		offset += 1;
	}
	if (*req == '[') {
		req += 1;
		offset += 1;
		stop_char = ']';
	} else {
		stop_char = ':';
	}

	if (offset >= len) {
		proxy_error_cli(ps, " no host in conn req, %.*s", len, req);

		return -1;
	}

	l = 0;
	while (*req != stop_char && l < sizeof(ps->host) && offset < len) {
		ps->host[l] = *req;
		req += 1;
		l += 1;
		offset += 1;
	}
	ps->host[l] = '\0';

	if (stop_char == ']')
		offset += 1;

	if (*req != ':' && *req != ' ') {
		proxy_error_cli(ps, "no port info in conn req, %.*s", len, req);

		return -1;
	}

	req += 1;
	l = 0;
	while (*req <= '9' && *req >= '0' && l < sizeof(ps->port)
	       && offset < len) {
		ps->port[l] = *req;
		req += 1;
		l += 1;
		offset += 1;
	}
	ps->port[l] = '\0';

	if (*req != ' ') {
		proxy_error_cli(ps, "port too long in conn req, %.*s", len,
		                req);

		return -1;
	}

	if (0 != str_to_port(ps->port, &port)) {
		proxy_error_cli(ps, "invalid port %s", ps->port);

		return -1;
	}

	if (1 == inet_pton(AF_INET, ps->host,
	                   &((struct sockaddr_in *) (&ps->svr))->sin_addr)) {
		((struct sockaddr_in *) (&ps->svr))->sin_family = AF_INET;
		((struct sockaddr_in *) (&ps->svr))->sin_port = htons(port);
	} else if (1 == inet_pton(AF_INET6, ps->host,
	                          &((struct sockaddr_in6 *) (&ps->svr))->sin6_addr)) {
		((struct sockaddr_in6 *) (&ps->svr))->sin6_family = AF_INET6;
		((struct sockaddr_in6 *) (&ps->svr))->sin6_port = htons(port);
	} else {
		bzero(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		// TODO 这里是同步的，不好
		ret = getaddrinfo(ps->host, ps->port, &hints, &result);
		if (ret != 0) {
			proxy_error_cli(ps, "conn req getaddrinfo return %d",
			                ret);

			return -1;
		}

		memcpy(&ps->svr, result->ai_addr, result->ai_addrlen);
		((struct sockaddr_in *) (&ps->svr))->sin_family = AF_INET;
		((struct sockaddr_in *) (&ps->svr))->sin_port = htons(port);

		freeaddrinfo(result);
	}

	return 0;
}

int proxy_process_connect_request(
	struct event *e,
	struct proxy_state *ps,
	const char *req,
	int len)
{
	if (0 != proxy_parse_connect_request(req, len, ps))
		goto ERROR;

	proxy_info_cli(ps, "connect request parsed, host: %s, port: %s",
	               ps->host, ps->port);

	if (ps->peep) {
		if (proxy_send_connected(e->fd) <= 0) {
			proxy_error_cli(ps, "fail to send connected");

			goto ERROR;
		}
		// proxy_send_connected直接骗客户端连上了，因为需要骗到sni再连接服务器
		// TODO 这里可以优化，两边同时搞，比较麻烦

		if (0 != proxy_add_read(ps, e->fd, SSL_DIR_2C,
		                        proxy_peek_sni, "proxy_peek_sni")) {
			proxy_error_cli(ps, "wait connect request fail"
			                    " to add read");

			return -1;
		}

		if (0 != proxy_add_timeout(ps, PROXY_TIMEOUT, SSL_DIR_2C,
		                           proxy_timeout, "timeout")) {
			proxy_error_cli(ps, "wait connect request fail"
			                    " to add timeout");

			return -1;
		}
	} else {
		/* TODO 正经的代理 */
		goto ERROR;
	}

	return 0;

ERROR:
	proxy_free_ps(ps);

	return -1;
}

int proxy_receive_connect_request(struct event *e)
{
	struct sockaddr addr;
	socklen_t len;
	struct proxy_state *ps;
	char buf[RECV_BUF_LEN];
	ssize_t rlen;
	struct sockaddr src;

	memcpy(&src, e->arg, sizeof(src));
	mem_free(e->arg);

	rlen = proxy_read(e->fd, buf, sizeof(buf));
	if (rlen <= 0) {
		log_info("connect request read nothing, err: %d, fd %d, svr %s",
		         errno, e->fd, sockaddr_string(&src));

		close(e->fd);

		return -1;
	}

	if (0 != strncasecmp(
		buf, PROXY_CONNECT_REQUEST_PREFIX,
		sizeof(PROXY_CONNECT_REQUEST_PREFIX) - 1)) {
		// TODO 有的客户端直接就ssl握手
		log_error("not proxy connect request, fd %d, peer %s",
		          e->fd, sockaddr_string(&src));

		close(e->fd);

		return -1;
	}

	log_debug("connect request: %.*s from %s, rlen: %d",
	          rlen - 1, buf, sockaddr_string(&src), rlen);

	len = sizeof(addr);
	if (0 != getsockname(e->fd, &addr, &len)) {
		log_error("fail to get self addr when process connect request,"
		          " fd %d, peer %s", e->fd, sockaddr_string(&src));

		close(e->fd);

		return -1;
	}

	ps = proxy_alloc_ps();
	if (NULL == ps) {
		log_error("fail to alloc ps when receiving connect request,"
		          " fd %d, peer %s", e->fd, sockaddr_string(&src));

		close(e->fd);

		return -1;
	}
	ps->cli_fd = e->fd;
	memcpy(&ps->cli, &src, sizeof(ps->cli));
	memcpy(&ps->cself, &addr, sizeof(ps->cself));

	proxy_debug_cli(ps, "connect request received");

	return proxy_process_connect_request(e, ps, buf, (int) rlen);
}

int proxy_connect_request_timeout(struct event *e)
{
	int fd;

	fd = (int) (long) e->arg;

	close(fd);

	return 0;
}

int proxy_accept_tcp_connect(struct event *e)
{
	struct sockaddr *addr;
	socklen_t len;

	int fd;

	event_add_read(e->scheduler, proxy_accept_tcp_connect, NULL, e->fd);

	addr = mem_alloc(sizeof(*addr));
	if (NULL == addr) {
		log_error("fail to alloc memory when accept");

		return -1;
	}

	len = sizeof(*addr);
	fd = accept(e->fd, addr, &len);
	if (fd < 0) {
		log_error("accept error: %d", errno);

		return -1;
	}

	log_info("%d accept, peer %s, fd %d", e->fd, sockaddr_string(addr), fd);

	event_add_read(e->scheduler, proxy_receive_connect_request, addr, fd);
	event_add_timer(e->scheduler, proxy_connect_request_timeout,
	                (void *) (long) fd, PROXY_TIMEOUT);

	return 0;
}

void proxy_init_ssl(struct event_scheduler *es, int listen)
{
	if (0 == OPENSSL_init_ssl(
		OPENSSL_INIT_ENGINE_ALL_BUILTIN
		| OPENSSL_INIT_ADD_ALL_CIPHERS
		| OPENSSL_INIT_ADD_ALL_DIGESTS
		| OPENSSL_INIT_ASYNC,
		NULL)) {
		log_error("OPENSSL_init_ssl, %s", PROXY_SSL_ERROR);

		exit(0);
	}

	ERR_clear_error();

	ENGINE_load_dynamic();

	if (0 == proxy_init_qat(es)) {
		log_debug("support async");

		m_proxy_opts.async = 1;
	}
	proxy_init_opts();

	proxy_init_self_ssl_ctx(PROXY_SELF_CERT_KEY_PATH,
	                        PROXY_SELF_CERT_PATH,
	                        X509_FILETYPE_PEM);

	event_add_read(es, proxy_accept_tcp_connect, NULL, listen);
}
