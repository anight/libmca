
AM_CPPFLAGS = $(AX_CPPFLAGS)

INCLUDES = \
	$(LIBEVENT_INCLUDES) \
	-I$(top_srcdir)/include

libmca_la_SOURCES = \
	mca.c \
	mca_net.c \
	mca_proto.c \
	mca_error.c \
	mca_charset.c \
	mca_charset_table.c \
	mca_state_machine.c \
	mca_buf.c \
	mca_sha1.c

include_HEADERS = \
	$(top_srcdir)/include/mca.h

libmca_la_LIBADD = $(LIBEVENT_LIBS)

EXTRA_DIST = libmca_config.h.in

lib_LTLIBRARIES = libmca.la

VERSION = -version-info 1:0:0

libmca_la_LDFLAGS = $(VERSION)

