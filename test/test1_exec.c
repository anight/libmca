
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <mca.h>

#include <event.h>
#include <evdns.h>

#include "test1.h"


#define my_debug printf


/* tunables */

const int mysql_conns_per_server = 4;
struct timeval mysql_connect_timeout = { .tv_sec = 30, .tv_usec = 0 };
struct timeval mysql_io_timeout = { .tv_sec = 3000, .tv_usec = 0 };

/* end of tunables */



struct mysql_conn;

struct server_task {
	struct db_server *s;
	int ref_cnt;
	int table_id;
	char resolved[sizeof("255.255.255.255")];
	struct mysql_conn *resolve_ready;
};

struct mysql_conn {
	struct mysql_conn *resolve_next;
	struct mysql_conn *prev, *next;
	mca *m;
	struct server_task *st;
	unsigned int db_index, table_index;
	int conn_id;
	int *conns_running;
	char *final_status;
	char *query;
	long rows_loaded;
};



int mysql_conn_get_next_table(struct server_task *st)
{
	if (st->table_id == st->s->tables_used) {
		return -1;
	}

	return st->table_id++;
}

void mysql_ready_fldesc(mca *m, void *arg)
{
//	struct mysql_conn *mc = arg;

//	my_debug("got a fldesc from %s(%d), Spot%u.User%u\n", mc->st->s->hostname, mc->conn_id, mc->db_index, mc->table_index);

//	mca_fldesc *fd;

//	mca_fldesc_get(m, &fd);

	/* process field descriptions here */

//	mca_fldesc_free(fd);
}

void mysql_ready_row(mca *m, void *arg)
{
	struct mysql_conn *mc = arg;

//	my_debug("got a row from %s(%d), Spot%u.User%u\n", mc->st->s->hostname, mc->conn_id, mc->db_index, mc->table_index);

	mca_row *r;

	r = mca_get_row(m);

	(void) r;

//	printf("%s(%d) Spot%u.User%u %s %s %s\n", mc->st->s->hostname, mc->conn_id, mc->db_index, mc->table_index,
//		r->data[0], r->data[1], r->data[2]);
	/* process row of data here */

	++mc->rows_loaded;

}

void mysql_conn_done(struct mysql_conn *mc, char *status)
{
	mc->final_status = strdup(status);

	if (mc->m) {
		mca_close(mc->m);
	}

	if (mc->query) {
		free(mc->query);
		mc->query = 0;
	}

	if (0 == --(*mc->conns_running)) {
		event_loopexit(0);
	}

	my_debug("%d connections left\n", *mc->conns_running);

	if (*mc->conns_running < 20) { /* the last few connections are always delaying - show them all */
		struct mysql_conn *mc1;

		for (mc1 = mc->prev; mc1; mc1 = mc1->prev) {
			if (!mc1->final_status) {
				my_debug("\t%s(%d) have %d tables left\n", mc1->st->s->hostname, mc1->conn_id, mc1->st->s->tables_used - mc1->st->table_id);
			}
		}

		for (mc1 = mc->next; mc1; mc1 = mc1->next) {
			if (!mc1->final_status) {
				my_debug("\t%s(%d) have %d tables left\n", mc1->st->s->hostname, mc1->conn_id, mc1->st->s->tables_used - mc1->st->table_id);
			}
		}
	}
}


void mysql_ready(mca *m, void *arg)
{
	struct mysql_conn *mc = arg;

	if (mc->query == NULL) { /* just connected */

		my_debug("mysql connection established: %s(%d) for Spot%u.User%u\n", mc->st->s->hostname, mc->conn_id, mc->db_index, mc->table_index);

		mca_set_callback(mc->m, MCA_CALLBACK_READY_FLDESC, mysql_ready_fldesc, mc);
		mca_set_callback(mc->m, MCA_CALLBACK_READY_ROW, mysql_ready_row, mc);

	}
	else { /* previous query completed, do next */

		int table_id;

		if (mc->query) {
			free(mc->query);
			mc->query = 0;
		}

		table_id = mysql_conn_get_next_table(mc->st);

		if (table_id == -1) { /* no more tasks for this connection */
			mysql_conn_done(mc, "Complete");
			return;
		}

		mc->db_index = mc->st->s->tables[table_id].db_index;
		mc->table_index = mc->st->s->tables[table_id].table_index;
	}

	asprintf(&mc->query, "select login, email, status from Spot%u.User%u limit 1", mc->db_index, mc->table_index);

	mca_query(m, mc->query);
}

void mysql_ready_error(mca *m, void *arg)
{
	struct mysql_conn *mc = arg;

	mysql_conn_done(mc, mca_error(mc->m));

	my_debug("error with connection %s(%d): %s\n", mc->st->s->hostname, mc->conn_id, mc->final_status);
}

void mysql_do_connect(struct mysql_conn *mc)
{
	mca_set_callback(mc->m, MCA_CALLBACK_READY, mysql_ready, mc);
	mca_set_callback(mc->m, MCA_CALLBACK_ERROR, mysql_ready_error, mc);

	mca_set_connect_timeout(mc->m, &mysql_connect_timeout);
	mca_set_read_timeout(mc->m, &mysql_io_timeout);
	mca_set_write_timeout(mc->m, &mysql_io_timeout);

	mca_set_charset_by_name(mc->m, "utf8_unicode_ci");

	mca_connect(mc->m, mc->st->resolved, mc->st->s->login, mc->st->s->password, NULL, 3306, NULL);
}

void mysql_hostname_resolved(int result, char type, int count, int ttl, void *addrs, void *arg)
{
	struct mysql_conn *mc = arg;

	if (result == DNS_ERR_NONE && type == DNS_IPv4_A && count > 0) {
		unsigned char *a = addrs;

		sprintf(mc->st->resolved, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);

		my_debug("resolved %s as %s\n", mc->st->s->hostname, mc->st->resolved);

		for (mc = mc->st->resolve_ready; mc; mc = mc->resolve_next) {
			mysql_do_connect(mc);
		}
	}
	else {
		/* todo: here we need more detailed description of the error */
		mysql_conn_done(mc, "Unable to resolve hostname");

		my_debug("resolve failed for %s: %s\n", mc->st->s->hostname, mc->final_status);
	}
}

int mysql_conn_new(struct mysql_conn **mcp, struct server_task *st)
{
	struct mysql_conn *mc;
	uint32_t addr;
	mca *m;
	int table_id;

	table_id = mysql_conn_get_next_table(st);

	if (table_id == -1) {
		return 0;
	}

	m = mca_init(NULL);

	if (!m) return -1;

	mc = malloc(sizeof(*mc));

	if (!mc) return -1;

	memset(mc, 0, sizeof(*mc));

	*mcp = mc;

	mc->m = m;
	mc->st = st;

	mc->db_index = st->s->tables[table_id].db_index;
	mc->table_index = st->s->tables[table_id].table_index;

	addr = inet_addr(st->s->hostname);

	if (INADDR_NONE == addr) { /* need to resolve first */

		if (!st->resolve_ready) { /* need to init resolve event */
			evdns_resolve_ipv4(st->s->hostname, 0, mysql_hostname_resolved, mc);
		}

		mc->resolve_next = st->resolve_ready;
		st->resolve_ready = mc;

	}
	else { /* can connect right now */

		unsigned char *a = (unsigned char *) &addr;
		sprintf(st->resolved, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
		mysql_do_connect(mc);

	}

	return 1;
}

int exec_all_spots(struct db_server *all_servers)
{
	int ret = 0;
	int i;
	struct db_server *s;
	struct mysql_conn *all_conns = 0;
	int conns_running = 0;
	struct mysql_conn *mc;

	event_init();

	evdns_resolv_conf_parse(DNS_OPTIONS_ALL, "/etc/resolv.conf");

	for (s = all_servers; s; s = s->next) {
		struct server_task *st = malloc(sizeof(*st));

		memset(st, 0, sizeof(*st));
		st->s = s;

		for (i = 0; i < mysql_conns_per_server; i++) {
			int r;

			r = mysql_conn_new(&mc, st);

			if (r < 0) return -1; /* unrecoverable error */
			if (r == 0) break; /* no more tables to select from */

			++mc->st->ref_cnt;

			mc->conn_id = i;

			mc->prev = 0;
			mc->next = all_conns;
			if (mc->next) {
				mc->next->prev = mc;
			}
			all_conns = mc;

			++conns_running;

			mc->conns_running = &conns_running;
		}
	}

	if (conns_running) {
		event_dispatch();
	}

	evdns_search_clear();

	evdns_clear_nameservers_and_suspend();

	evdns_shutdown(0);

	event_base_free(0);

	int total_rows = 0;

	for (mc = all_conns; mc; ) {
		struct mysql_conn *curr = mc;
		my_debug("connection %s(%d): %s\n", curr->st->s->hostname, curr->conn_id, curr->final_status);
		total_rows += mc->rows_loaded;
		free(curr->final_status);
		mc = mc->next;
		if (0 == --curr->st->ref_cnt) {
			free(curr->st);
		}
		free(curr);
	}

	my_debug("total_rows = %d\n", total_rows);

	return ret;
}

