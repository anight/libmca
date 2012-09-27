
	/* $Id: mca_proto.h,v 1.2 2008/01/29 22:31:46 anight Exp $ */
	/* (c) Andrei Nigmatulin, 2007 */

#ifndef _MCA_PROTO_H_
#define _MCA_PROTO_H_ 1

/* borrowed from mysql_com.h */

#define MCA_CLIENT_LONG_PASSWORD	1	/* new more secure passwords */
#define MCA_CLIENT_FOUND_ROWS	2	/* Found instead of affected rows */
#define MCA_CLIENT_LONG_FLAG	4	/* Get all column flags */
#define MCA_CLIENT_CONNECT_WITH_DB	8	/* One can specify db on connect */
#define MCA_CLIENT_NO_SCHEMA	16	/* Don't allow database.table.column */
#define MCA_CLIENT_COMPRESS		32	/* Can use compression protocol */
#define MCA_CLIENT_ODBC		64	/* Odbc client */
#define MCA_CLIENT_LOCAL_FILES	128	/* Can use LOAD DATA LOCAL */
#define MCA_CLIENT_IGNORE_SPACE	256	/* Ignore spaces before '(' */
#define MCA_CLIENT_PROTOCOL_41	512	/* New 4.1 protocol */
#define MCA_CLIENT_INTERACTIVE	1024	/* This is an interactive client */
#define MCA_CLIENT_SSL              2048	/* Switch to SSL after handshake */
#define MCA_CLIENT_IGNORE_SIGPIPE   4096    /* IGNORE sigpipes */
#define MCA_CLIENT_TRANSACTIONS	8192	/* Client knows about transactions */
#define MCA_CLIENT_RESERVED         16384   /* Old flag for 4.1 protocol  */
#define MCA_CLIENT_SECURE_CONNECTION 32768  /* New 4.1 authentication */
#define MCA_CLIENT_MULTI_STATEMENTS 65536   /* Enable/disable multi-stmt support */
#define MCA_CLIENT_MULTI_RESULTS    131072  /* Enable/disable multi-results */
#define MCA_CLIENT_REMEMBER_OPTIONS	(((ulong) 1) << 31)


#define MCA_CMD_QUERY 3

#endif
