
	/* $Id: mca_proto.c,v 1.26 2008/11/05 14:09:24 anight Exp $ */
	/* (c) Andrei Nigmatulin, 2007 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mca.h>
#include <mca_proto.h>
#include <mca_private.h>

#include "mca_sha1.h"

#define MCA_SCRAMBLE_41_LENGTH 20
#define MCA_NULL -1ULL


#define min(a, b) ((a) < (b) ? (a) : (b))


static uint64_t mca_parse_uint64(char *buf, size_t *off)
{
	unsigned char *b = (unsigned char *) buf + *off;

	*off += 8;

	return     (uint64_t) (b[0] + (b[1] << 8) +
	           (b[2] << 16) + (b[3] << 24)) +
	           (((uint64_t) (b[4] + (b[5] << 8) +
	           (b[6] << 16) + (b[7] << 24))) << 32);
}

static uint32_t mca_parse_uint32(char *buf, size_t *off)
{
	unsigned char *b = (unsigned char *) buf + *off;

	*off += 4;

	return b[0] + (b[1] << 8) +
		(b[2] << 16) + (b[3] << 24);
}

static uint32_t mca_parse_uint24(char *buf, size_t *off)
{
	unsigned char *b = (unsigned char *) buf + *off;

	*off += 3;

	return b[0] + (b[1] << 8) + (b[2] << 16);
}

static uint16_t mca_parse_uint16(char *buf, size_t *off)
{
	unsigned char *b = (unsigned char *) buf + *off;

	*off += 2;

	return b[0] + (b[1] << 8);
}

static uint8_t mca_parse_uint8(char *buf, size_t *off)
{
	unsigned char *b = (unsigned char *) buf + *off;

	*off += 1;

	return b[0];
}

static unsigned long long mca_parse_fle(char *buf, size_t *off)
{
	unsigned char *b = (unsigned char *) buf + *off;

	if (*b < 251) {
		*off += 1;
		return *b;
	}

	*off += 1;

	if (*b == 251) {
		return MCA_NULL;
	}

	if (*b == 252) {
		return mca_parse_uint16(buf, off);
	}

	if (*b == 253) {
		return mca_parse_uint24(buf, off);
	}

	return mca_parse_uint64(buf, off);
}

static int mca_fle_length(char *buf)
{
	unsigned char *b = (unsigned char *) buf;

	switch (*b) {
		case 251 :
			return 1;
		case 252 :
			return 3;
		case 253 :
			return 4;
		case 254 :
			return 9;
		case 255 :
			return -1;
		default :
			return 1;
	}
}

static void mca_store_uint32(char *buf, size_t *off, unsigned int n)
{
	unsigned char *b = (unsigned char *) buf + *off;

	*b++ = (n & 0xff);
	*b++ = ((n >> 8) & 0xff);
	*b++ = ((n >> 16) & 0xff);
	*b++ = ((n >> 24) & 0xff);

	*off += 4;
}

static void mca_store_uint24(char *buf, size_t *off, unsigned int n)
{
	unsigned char *b = (unsigned char *) buf + *off;

	*b++ = (n & 0xff);
	*b++ = ((n >> 8) & 0xff);
	*b++ = ((n >> 16) & 0xff);

	*off += 3;
}

static void mca_store_uint8(char *buf, size_t *off, unsigned int n)
{
	unsigned char *b = (unsigned char *) buf + *off;

	*b++ = (n & 0xff);

	*off += 1;
}

static void memxor(char *to, unsigned char *s1, unsigned char *s2, int len)
{
	unsigned char *s1_end = s1 + len;

	while (s1 < s1_end) {
		*to++ = *s1++ ^ *s2++;
	}
}

static void mca_packet_write_finalize(mca *m, int len)
{
	m->write_packet_buf[0] = (len & 0xff);
	m->write_packet_buf[1] = ((len >> 8) & 0xff);
	m->write_packet_buf[2] = ((len >> 16) & 0xff);
	m->write_packet_buf[3] = m->packet_id++;

	m->write_packet_len = NET_HEADER_SIZE + len;
}

static void mca_parse_simple_response(mca *m, char *buf)
{
	size_t off = 0;
	int field_count;

	field_count = mca_parse_fle(buf, &off);

	(void) field_count;

	m->server.affected_rows = mca_parse_fle(buf, &off);
	m->server.insert_id = mca_parse_fle(buf, &off);
	m->server.status = mca_parse_uint16(buf, &off);
	m->server.warning_count = mca_parse_uint16(buf, &off);
}

static void mca_scramble_password_41(char *dst, char *digest, char *password)
{
	SHA1Context ctx;
	unsigned char hash1[SHA1HashSize];
	unsigned char hash2[SHA1HashSize];

	mca_SHA1Reset(&ctx);

	mca_SHA1Input(&ctx, (unsigned char *) password, strlen(password));

	mca_SHA1Result(&ctx, hash1);

	mca_SHA1Reset(&ctx);
	mca_SHA1Input(&ctx, hash1, SHA1HashSize);
	mca_SHA1Result(&ctx, hash2);

	mca_SHA1Reset(&ctx);
	mca_SHA1Input(&ctx, (unsigned char *) digest, MCA_SCRAMBLE_41_LENGTH);
	mca_SHA1Input(&ctx, hash2, SHA1HashSize);

	mca_SHA1Result(&ctx, (unsigned char *) dst);

	memxor(dst, (unsigned char *) dst, hash1, MCA_SCRAMBLE_41_LENGTH);
}

mca_state mca_handshake_process(mca *m)
{
	size_t off, sz;
	char scramble[MCA_SCRAMBLE_41_LENGTH + 1];
	int username_len, db_len;

	/* 1) parse handshake packet */

	if (m->read_packet_buf[NET_HEADER_SIZE] != '\x0a') {
		mca_set_error(m, 0, "unknown protocol '%02x' (is it mysql host/port?)", m->read_packet_buf[NET_HEADER_SIZE]);
		return MCA_STATE_ERROR;
	}

	for (off = NET_HEADER_SIZE + 1; m->read_packet_buf[off] &&
					off < m->read_packet_len + NET_HEADER_SIZE; off++);

	if (m->read_packet_buf[off] != '\0') {
		mca_set_error(m, 0, "handshake parse error (1)");
		return MCA_STATE_ERROR;
	}

	++off;

	m->server.version = strdup(m->read_packet_buf + NET_HEADER_SIZE + 1);

	/* we expect this number of octets minimum when talking to 4.1 server */
	if (m->read_packet_len + NET_HEADER_SIZE - off < 31) {
		mca_set_error(m, 0, "handshake parse error (2)");
		return MCA_STATE_ERROR;
	}

	m->server.thread_id = mca_parse_uint32(m->read_packet_buf, &off);

	memcpy(scramble, &m->read_packet_buf[off], 8);
	scramble[8] = '\0';

	off += 9;

	m->server.caps = mca_parse_uint16(m->read_packet_buf, &off);

	m->server.charset = mca_parse_uint8(m->read_packet_buf, &off);

	m->server.status = mca_parse_uint16(m->read_packet_buf, &off);

	off += 13;

	if (m->read_packet_len + NET_HEADER_SIZE - off >= 13) {
		memcpy(scramble+8, &m->read_packet_buf[off], 12);
		scramble[MCA_SCRAMBLE_41_LENGTH] = '\0';
	}
	else {
		m->server.caps &= ~MCA_CLIENT_SECURE_CONNECTION;
	}

	/* 2) compose handshake response packet */

	if (m->connection.password && m->connection.password[0] &&
				0 == (m->server.caps & MCA_CLIENT_SECURE_CONNECTION)) {
		mca_set_error(m, 0, "will not send password in old-fashioned manner");
		return MCA_STATE_ERROR;
	}

	username_len = strlen(m->connection.username);
	db_len = m->connection.db ? strlen(m->connection.db) : 0;

	sz = 13 + 23 + username_len + 1 + MCA_SCRAMBLE_41_LENGTH + 1 + db_len + 1;

	if (MCA_OK != mca_packet_write_alloc(m, sz)) {
		return MCA_STATE_ERROR;
	}

	if (m->connection.db) {
		m->client.caps |= MCA_CLIENT_CONNECT_WITH_DB;
	}

	off = NET_HEADER_SIZE;

	mca_store_uint32(m->write_packet_buf, &off, m->client.caps);

	mca_store_uint32(m->write_packet_buf, &off, m->client.max_packet_length);

	mca_store_uint8(m->write_packet_buf, &off, m->client.charset->number);

	memset(m->write_packet_buf + off, 0, 23);

	off += 23;

	strcpy(m->write_packet_buf + off, m->connection.username);

	off += username_len + 1;

	if (m->connection.password && m->connection.password[0]) {
		m->write_packet_buf[off++] = MCA_SCRAMBLE_41_LENGTH;
		mca_scramble_password_41(m->write_packet_buf + off, scramble, m->connection.password);
		off += MCA_SCRAMBLE_41_LENGTH;
	}
	else {
		m->write_packet_buf[off++] = '\0';
	}

	if (m->connection.db) {
		strcpy(m->write_packet_buf + off, m->connection.db);

		off += db_len + 1;
	}

	mca_packet_write_finalize(m, off - NET_HEADER_SIZE);

	return MCA_STATE_WRITING_HANDSHAKE;
}

void mca_parse_error(mca *m)
{
	size_t off;

	if (m->read_packet_len > 4) {
		off = NET_HEADER_SIZE + 1;

		m->server.last_error_code = mca_parse_uint16(m->read_packet_buf, &off);

		mca_set_error(m, 0, "mysql error: %s", m->read_packet_buf + off);
	}
	else {
		mca_set_error(m, 0, "mysql unknown error");
	}
}

mca_state mca_handshake_process2(mca *m)
{
	if (m->read_packet_len < 1) {
		mca_set_error(m, 0, "too small packet in response to auth");

		return MCA_STATE_ERROR;
	}

	if (m->read_packet_buf[NET_HEADER_SIZE] == '\xff') {
		mca_parse_error(m);
		return MCA_STATE_ERROR;
	}

	mca_parse_simple_response(m, &m->read_packet_buf[NET_HEADER_SIZE]);

	return MCA_STATE_READY;
}

mca_state mca_result_process(mca *m)
{
	size_t off = NET_HEADER_SIZE;
	size_t field_count;

	if (m->read_packet_len >= 1 && m->read_packet_buf[off] == '\xff') {
		mca_parse_error(m);
		return MCA_STATE_ERROR;
	}

	int fle_length;

	if (m->read_packet_len > 0 && (fle_length = mca_fle_length(&m->read_packet_buf[off])) > 0 && m->read_packet_len >= (unsigned) fle_length) {
		field_count = mca_parse_fle(m->read_packet_buf, &off);
		if (field_count == 0) {
			mca_parse_simple_response(m, &m->read_packet_buf[NET_HEADER_SIZE]);
			return MCA_STATE_READY;
		}
	}
	else {
		mca_set_error(m, 0, "mca_result_process(): packet parse error");
		return MCA_STATE_ERROR;
	}

	if (m->result_fields_allocated < field_count) {
		size_t fields_to_allocate = 32;
		void *ptr;

		while (fields_to_allocate < field_count) fields_to_allocate <<= 1;

		ptr = realloc(m->result_row.data, fields_to_allocate * sizeof(char *));

		if (ptr == NULL) {
			mca_set_error(m, 0, "out of memory");
			return MCA_STATE_ERROR;
		}

		m->result_row.data = ptr;

		ptr = realloc(m->result_row.length, fields_to_allocate * sizeof(int));

		if (ptr == NULL) {
			mca_set_error(m, 0, "out of memory");
			return MCA_STATE_ERROR;
		}

		m->result_row.length = ptr;

		m->result_fields_allocated = fields_to_allocate;
	}

	if (mca_have_cb(m, READY_FLDESC)) {

		if (m->fldesc_allocated < field_count) {
			size_t to_allocate = 32;
			void *ptr;

			while (to_allocate < field_count) to_allocate <<= 1;

			ptr = realloc(m->fldesc, to_allocate * sizeof(mca_fldesc));

			if (ptr == NULL) {
				mca_set_error(m, 0, "out of memory");
				return MCA_STATE_ERROR;
			}

			m->fldesc_allocated = to_allocate;
			m->fldesc = ptr;
		}

	}

	m->fldesc_used = 0;

	m->result_fields = field_count;

	return MCA_STATE_READING_RESULT_FLDESC;
}

static int mca_get_fldesc(mca *m, mca_fldesc *f)
{
	int i;
	size_t r, off, len, len_len;

	r = m->read_packet_len;
	off = NET_HEADER_SIZE;

	for (i = 0; i < 5; i++) {
		if (r >= 1) {
			len_len = mca_fle_length(&m->read_packet_buf[off]);
			if (r >= len_len) {
				size_t off2 = off;
				len = mca_parse_fle(m->read_packet_buf, &off2);

				if (r < len_len + len) {
					mca_set_error(m, 0, "mca_get_fldesc(): truncated packet (1)");
					return -1;
				}

				if (i == 4) {
					int copy_len = min(len, sizeof(f->name) - 1);
					strncpy(f->name, m->read_packet_buf + off + len_len, copy_len);
					f->name[copy_len] = '\0';
					f->length = len;
				}

				off += len_len + len;
				r -= len_len + len;
			}
			else {
				mca_set_error(m, 0, "mca_get_fldesc(): truncated packet (2)");
				return -1;
			}
		}
		else {
			mca_set_error(m, 0, "mca_get_fldesc(): truncated packet (3)");
			return -1;
		}
	}

	return 0;
}

mca_state mca_result_process_fldesc(mca *m)
{
	if ((m->read_packet_len == 1 || m->read_packet_len == 5) && m->read_packet_buf[NET_HEADER_SIZE] == '\xfe') {

		if (mca_have_cb(m, READY_FLDESC) && m->fldesc_used < m->result_fields) {
			mca_set_error(m, 0, "mca_result_process_fldesc(): not enough fldesc packets");
			return MCA_STATE_ERROR;
		}

		return MCA_STATE_READY_FLDESC;
	}

	if (mca_have_cb(m, READY_FLDESC)) {

		if (m->fldesc_used == m->result_fields) {
			mca_set_error(m, 0, "mca_result_process_fldesc(): too many fldesc packets");
			return MCA_STATE_ERROR;
		}

		if (0 > mca_get_fldesc(m, &m->fldesc[m->fldesc_used])) {
			return MCA_STATE_ERROR;
		}

		++m->fldesc_used;
	}

	return MCA_STATE_READING_RESULT_FLDESC;
}

mca_state mca_result_process_row(mca *m)
{
	size_t off;

	if (m->read_packet_len == 5 && m->read_packet_buf[NET_HEADER_SIZE] == '\xfe') {
		off = NET_HEADER_SIZE + 1;

		m->server.warning_count = mca_parse_uint16(m->read_packet_buf, &off);
		m->server.status = mca_parse_uint16(m->read_packet_buf, &off);

		return MCA_STATE_READY;
	}

	return MCA_STATE_READY_ROW;
}

/* sub-interface fn */

int mca_query_send(mca *m, char *query)
{
	int ret;
	size_t off;
	int query_len;

	query_len = strlen(query);

	ret = mca_packet_write_alloc(m, 1 + query_len);

	if (ret != MCA_OK) {
		return ret;
	}

	off = NET_HEADER_SIZE;

	mca_store_uint8(m->write_packet_buf, &off, MCA_CMD_QUERY);

	memcpy(m->write_packet_buf + off, query, query_len);

	m->state = MCA_STATE_WRITING_QUERY;

	mca_packet_write_finalize(m, 1 + query_len);

	return MCA_OK;
}

mca_row *mca_get_row(mca *m)
{
	int i;
	size_t r, off, len, len_len;
	mca_row *row = &m->result_row;

	r = m->read_packet_len;
	off = NET_HEADER_SIZE;

	if (m->row_parsed) {
		return row;
	}

	for (i = 0; (size_t) i < m->result_fields; i++) {
		if (r >= 1) {
			len_len = mca_fle_length(&m->read_packet_buf[off]);
			if (r >= len_len) {
				if (m->read_packet_buf[off] == '\xfb') { /* NULL */
					len = 0;
					row->data[i] = 0;
					row->length[i] = -1;
				}
				else { /* NOT NULL */
					size_t off2 = off;
					len = mca_parse_fle(m->read_packet_buf, &off2);

					if (r < len_len + len) {
						mca_set_error(m, 0, "mca_get_row(): truncated packet (1)");
						return NULL;
					}

					row->data[i] = m->read_packet_buf + off + len_len;
					row->length[i] = len;
				}

				if (i > 0) {
					m->read_packet_buf[off] = '\0';
				}

				off += len_len + len;
				r -= len_len + len;
			}
			else {
				mca_set_error(m, 0, "mca_get_row(): truncated packet (2)");
				return NULL;
			}
		}
		else {
			mca_set_error(m, 0, "mca_get_row(): truncated packet (3)");
			return NULL;
		}
	}

	if (r) {
		mca_set_error(m, 0, "mca_get_row(): extra bytes at the end");
		return NULL;
	}

	m->row_parsed = 1;

	return row;
}

