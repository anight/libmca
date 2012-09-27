
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test1.h"
#include "test1_exec.h"


void db_server_add(struct db_server **all_servers, struct db_server *s)
{
	s->next = *all_servers;

	if (*all_servers) {
		(*all_servers)->prev = s;
	}

	*all_servers = s;
}

struct db_server *db_server_new(char *hostname, char *login, char *password)
{
	struct db_server *s;

	s = malloc(sizeof(*s));

	if (!s) return NULL;

	memset(s, 0, sizeof(*s));

	s->hostname = strdup(hostname);
	s->login = strdup(login);
	s->password = strdup(password);

	return s;
}

int db_table_new(struct db_server *s, unsigned int db_index, unsigned int table_index)
{
	if (s->tables_allocated == s->tables_used) {
		int new_size = s->tables_allocated + 4096;
		void *p = realloc(s->tables, sizeof(struct db_table) * new_size);

		if (!p) return -1;

		s->tables = p;
		s->tables_allocated = new_size;
	}

	s->tables[s->tables_used].db_index = db_index;
	s->tables[s->tables_used].table_index = table_index;

	++s->tables_used;

	return 0;
}

int load_all_spots(struct db_server **all_servers, FILE *f)
{
	int ret = 0;
	char buf[1024];
	struct db_server *s = NULL;

	while (fgets(buf, sizeof(buf), f)) {
		{
			char hostname[64], login[64], password[64];

			if (3 == sscanf(buf, "s %63s %63s %63s", hostname, login, password)) {
				if (s) db_server_add(all_servers, s);
				s = db_server_new(hostname, login, password);
				continue;
			}
		}

		{
			unsigned int db_index, table_index;

			if (2 == sscanf(buf, "t %u %u", &db_index, &table_index)) {
				db_table_new(s, db_index, table_index);
				continue;
			}
		}

		fprintf(stderr, "unable to parse %s", buf);
		ret = -1;
		break;
	}

	if (ret == 0 && s) db_server_add(all_servers, s);

	return ret;
}

int main(int argc, char **argv)
{
	FILE *in;
	struct db_server *s, *all_servers = NULL;

	in = fopen("data.txt", "r");

	if (!in) {
		perror("fopen");
		return 1;
	}

	load_all_spots(&all_servers, in);

	fclose(in);

	exec_all_spots(all_servers);

	for (s = all_servers; s; ) {
		struct db_server *curr = s;
		free(curr->hostname);
		free(curr->login);
		free(curr->password);
		free(curr->tables);
		s = s->next;
		free(curr);
	}

	return 0;
}
