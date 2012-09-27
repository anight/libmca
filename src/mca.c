
	/* $Id: mca.c,v 1.26 2008/11/05 09:05:01 tony Exp $ */
	/* (c) Andrei Nigmatulin, 2007 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <mca.h>
#include <mca_proto.h>
#include <mca_private.h>


mca *mca_init(mca *m)
{
	if (!m) {
		m = malloc(sizeof(mca));

		if (!m) return NULL;

		memset(m, 0, sizeof(mca));

		m->is_allocated = 1;
	}
	else {
		memset(m, 0, sizeof(mca));
	}
	
	m->sock = -1;

	m->connect_timeout.tv_sec = 60;
	m->read_timeout.tv_sec = 300;
	m->write_timeout.tv_sec = 300;

	m->client.max_packet_length = 16 * 1024 * 1024;
	m->client.caps = MCA_CLIENT_LONG_PASSWORD | MCA_CLIENT_LONG_FLAG |
		MCA_CLIENT_PROTOCOL_41 | MCA_CLIENT_SECURE_CONNECTION | MCA_CLIENT_TRANSACTIONS;

	return m;
}

void mca_set_callback(mca *m, int type, void (*cb)(mca *, void *), void *arg)
{
	if (type >= 0 && type < MCA_CALLBACK_LAST) {
		m->callbacks[type].cb = cb;
		m->callbacks[type].arg = arg;
	}
}

int mca_connect(mca *m, char *host, char *username, char *password, char *db, int port, char *unix_socket)
{
	int ret;

	if (m->sock != -1) {
		mca_set_error(m, 0, "mca_connect(): already connected");
		return MCA_ERROR_USER;
	}

	if ((unix_socket && host) || (!unix_socket && !host)) {
		mca_set_error(m, 0, "mca_connect(): only one of either host or unix_socket should be specified");
		return MCA_ERROR_USER;
	}

	if (strlen(username) > 16) {
		mca_set_error(m, 0, "mca_connect(): username must not exceed 16 chars");
		return MCA_ERROR_USER;
	}

	if (!m->client.charset) {
		m->client.charset = mca_charset_get_default();
	}

	m->connection.username = strdup(username);

	if (password) {
		m->connection.password = strdup(password);
	}

	if (db) {
		m->connection.db = strdup(db);
	}

	if (unix_socket) {
		ret = mca_connect_unix(m, unix_socket);
	}
	else {
		ret = mca_connect_inet(m, host, port);
	}

	if (ret == MCA_OK) {
		mca_ev_activate(m, EV_WRITE);
	}

	return ret;
}

int mca_query(mca *m, char *query)
{
	int ret;

	ret = mca_query_send(m, query);

	if (ret == MCA_OK) {
		mca_ev_activate(m, EV_WRITE);
	}

	return ret;
}

char *mca_error(mca *m)
{
	return m->last_error;
}

void mca_set_connect_timeout(mca *m, struct timeval *tv)
{
	m->connect_timeout = *tv;
}

void mca_set_read_timeout(mca *m, struct timeval *tv)
{
	m->read_timeout = *tv;
}

void mca_set_write_timeout(mca *m, struct timeval *tv)
{
	m->write_timeout = *tv;
}

int mca_set_charset_by_csname(mca *m, char *csname)
{
	m->client.charset = mca_charset_get_by_csname(csname);

	if (!m->client.charset) {
		return MCA_ERROR_USER;
	}

	return MCA_OK;
}

int mca_set_charset_by_name(mca *m, char *name)
{
	m->client.charset = mca_charset_get_by_name(name);

	if (!m->client.charset) {
		return MCA_ERROR_USER;
	}

	return MCA_OK;
}

void mca_free(mca *m)
{
	if (m->is_allocated) {
		free(m);
	}
}

void mca_suspend(mca *m)
{
	m->is_suspended = 1;
	mca_ev_update(m, 0, 0);
}

void mca_resume(mca *m)
{
	m->is_suspended = 0;
	mca_ev_activate(m, EV_READ);
}

void mca_close(mca *m)
{
	mca_ev_update(m, 0, 0);

	if (m->sock != -1) {
		close(m->sock);
		m->sock = -1;
	}

	m->state = MCA_STATE_CLOSING;

	free(m->connection.username);
	m->connection.username = 0;

	free(m->connection.password);
	m->connection.password = 0;

	free(m->connection.db);
	m->connection.db = 0;

	free(m->client.charset_name);
	m->client.charset_name = 0;

	free(m->server.version);
	m->server.version = 0;

	free(m->buf);
	m->buf = 0;

	free(m->result_row.data);
	m->result_row.data = 0;

	free(m->result_row.length);
	m->result_row.length = 0;

	free(m->fldesc);
	m->fldesc = 0;

	if (!m->in_handler) {
		mca_free(m);
	}
}
