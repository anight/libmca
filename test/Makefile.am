
INCLUDES = -I$(top_srcdir)/include

CFLAGS += -D_GNU_SOURCE

noinst_PROGRAMS = test1
test1_SOURCES = test1.c test1_exec.c
# test1_LDFLAGS = -static
test1_LDADD = $(top_builddir)/src/libmca.la

