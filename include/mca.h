
	/* $Id: mca.h,v 1.26 2008/11/05 09:05:01 tony Exp $ */
	/* (c) Andrei Nigmatulin, 2007 */


#ifndef _MCA_H_
#define _MCA_H_ 1


#include <stdint.h>
#include <sys/types.h>
#include <event.h>


#define MYSQL_DEFAULT_PORT       3306


typedef struct mca_s mca;
typedef struct mca_callback_s mca_callback;

struct mca_callback_s {
	void (*cb)(mca *, void *);
	void *arg;
};

enum {
	MCA_CALLBACK_ERROR,
	MCA_CALLBACK_READY,
	MCA_CALLBACK_READY_FLDESC,
	MCA_CALLBACK_READY_ROW,
	MCA_CALLBACK_LAST
};

struct mca_charset;

typedef enum mca_state_e {
	MCA_STATE_NONE = 0,
	MCA_STATE_ERROR,
	MCA_STATE_CONNECTING,
	MCA_STATE_CLOSING,
	MCA_STATE_READING_HANDSHAKE,
	MCA_STATE_WRITING_HANDSHAKE,
	MCA_STATE_READING_AUTH_RESULT,
	MCA_STATE_READY,
	MCA_STATE_WRITING_QUERY,
	MCA_STATE_READING_RESULT,
	MCA_STATE_READING_RESULT_FLDESC,
	MCA_STATE_READY_FLDESC,
	MCA_STATE_READING_RESULT_ROWS,
	MCA_STATE_READY_ROW
} mca_state;

typedef struct mca_row_s mca_row;
typedef struct mca_fldesc_s mca_fldesc;

struct mca_row_s {
	char **data;
	int *length;
};

struct mca_fldesc_s {
	char name[256 - sizeof(int)];
	int length;
};

struct mca_s {
	int sock;

	mca_state state;

	struct event ev;
	int ev_active;

	unsigned in_handler:1;
	unsigned is_suspended:1;
	unsigned is_allocated:1;
	unsigned row_parsed:1;

	struct {
		char *username, *password, *db;
	} connection;

	mca_callback callbacks[MCA_CALLBACK_LAST];

	struct {
		long max_packet_length;
		long caps;
		char *charset_name;
		const struct mca_charset *charset;
	} client;

	struct {
		char               *version;
		uint32_t            thread_id;
		uint16_t            caps;
		uint8_t             charset;
		uint16_t            status;
		unsigned long long  affected_rows;
		unsigned long long  insert_id;
		uint16_t            warning_count;
		uint16_t            last_error_code;
	} server;

	char last_error[1024];

	char read_hdr_buf[4];
	size_t read_hdr_off;

	char *read_packet_buf;
	size_t read_packet_off;
	size_t read_packet_len;

	char *write_packet_buf;
	size_t write_packet_off;
	size_t write_packet_len;
	unsigned char packet_id;

	char *buf;
	size_t buf_allocated;

	size_t result_fields;

	size_t result_fields_allocated;
	mca_row result_row;

	mca_fldesc *fldesc;
	size_t fldesc_used, fldesc_allocated;

	struct timeval read_timeout, write_timeout, connect_timeout;
};

mca *mca_init(mca *m);
int mca_connect(mca *m, char *host, char *username, char *password,
				char *db, int port, char *unix_socket);
int mca_query(mca *m, char *query);
mca_row *mca_get_row(mca *m);
char *mca_error(mca *m);
void mca_close(mca *m);

void mca_suspend(mca *m);
void mca_resume(mca *m);

int mca_set_charset_by_csname(mca *m, char *csname);
int mca_set_charset_by_name(mca *m, char *name);

void mca_set_callback(mca *m, int type, void (*cb)(mca *, void *), void *arg);
void mca_set_connect_timeout(mca *m, struct timeval *tv);
void mca_set_read_timeout(mca *m, struct timeval *tv);
void mca_set_write_timeout(mca *m, struct timeval *tv);

enum {
	MCA_OK = 0,
	MCA_ERROR = -1,
	MCA_ERROR_USER = -2,
	MCA_EAGAIN = -3
};

#endif
