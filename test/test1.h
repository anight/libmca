
struct db_server;
struct db_table;

struct db_server {
	struct db_server *prev, *next;
	char *hostname;
	char *login;
	char *password;
	int tables_allocated, tables_used;
	struct db_table *tables;
};

struct db_table {
	unsigned int db_index, table_index;
};

