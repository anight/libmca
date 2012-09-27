
	/* $Id: mca_private.h,v 1.19 2008/11/05 09:05:01 tony Exp $ */
	/* (c) Andrei Nigmatulin, 2007 */

#ifndef _MCA_PRIVATE_H_
#define _MCA_PRIVATE_H_ 1

#include <sys/time.h> /* for struct timeval */

#define NET_HEADER_SIZE 4
#define USERNAME_LENGTH 16

int mca_connect_unix(mca *m, char *unix_socket);
int mca_connect_inet(mca *m, char *host, int port);
void mca_packet_read_reset(mca *m);
int mca_packet_write_alloc(mca *m, size_t s);
int mca_packet_read(mca *m);
int mca_packet_write(mca *m);
mca_state mca_handshake_process(mca *m);
mca_state mca_handshake_process2(mca *m);
mca_state mca_result_process(mca *m);
mca_state mca_result_process_fldesc(mca *m);
mca_state mca_result_process_row(mca *m);
int mca_query_send(mca *m, char *query);
void *mca_alloc_buf(mca *m, size_t s);
mca_row *mca_alloc_row();
void mca_ev_update(mca *m, int e, struct timeval *tv);
void mca_ev_activate(mca *m, int e);
void mca_free(mca *m);
void mca_set_error(mca *m, int use_errno, char *fmt, ...);

struct mca_charset {
	int number;
	const char *csname;
	const char *name;
};

const struct mca_charset *mca_charset_get_default();
const struct mca_charset *mca_charset_get_by_name(char *name);
const struct mca_charset *mca_charset_get_by_csname(char *csname);

#define mca_have_cb(m, type) (0 != m->callbacks[MCA_CALLBACK_##type].cb)

#define mca_cb(m, type) \
	do { \
		if (mca_have_cb(m, type)) { \
			m->callbacks[MCA_CALLBACK_##type].cb(m, m->callbacks[MCA_CALLBACK_##type].arg); \
		} \
	} while (0)

#endif
