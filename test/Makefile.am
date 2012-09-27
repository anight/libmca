
INCLUDES = \
	-I$(top_srcdir)/include \
	$(LIBEVENT_INCLUDES)

CFLAGS += $(AX_CPPFLAGS) -D_GNU_SOURCE

noinst_PROGRAMS = test1
test1_SOURCES = test1.c test1_exec.c
test1_LDADD = $(top_builddir)/src/libmca.la

