#include <my_global.h>
#include <mysql.h>
#include <m_ctype.h>
#include <my_sys.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	MYSQL *m = mysql_init(0);
	MYSQL_RES *res;
	MYSQL_ROW data;

	DBUG_PROCESS(argv[0]);
	DBUG_PUSH(argv[1]);

	mysql_options(m, MYSQL_SET_CHARSET_NAME, "utf8");

	if (NULL == mysql_real_connect(m, "127.0.0.1", "root", "", "mysql", 3306, 0, /* "/var/lib/mysql/mysql.sock", */0)) {
		fprintf(stderr, "connection failed: %s\n", mysql_error(m));
		return 1;
	}

	CHARSET_INFO **cs;
	int i = 0;

	for (cs = all_charsets; cs < all_charsets + 256; ++cs, ++i) {
		if (*cs) {
			printf("\t{ %d, \"%s\", \"%s\" },\n", (*cs)->number, (*cs)->csname, (*cs)->name);
		}
		else {
			printf("\t{ %d, 0, 0 },\n", i);
		}
	}

	fprintf(stderr, "[+] connected\n");

	if (mysql_query(m, "select * from db") != 0) {
		fprintf(stderr, "query failed: %s\n", mysql_error(m));
		return 1;
	}

	fprintf(stderr, "[+] query sent\n");

	res = mysql_use_result(m);

	if (!res) {
		fprintf(stderr, "use result failed: %s\n", mysql_error(m));
		return 1;
	}

	while ( (data = mysql_fetch_row(res)) ) {
		printf("%s %s %s\n", data[0], data[1], data[2]);
	}

}
