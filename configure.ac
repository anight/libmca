AC_INIT(libmca, 0.2, andrei.nigmatulin@gmail.com)
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADER([src/libmca_config.h])

AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(inet_addr, nsl)

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

AX_CPPFLAGS="-W -Wall -Werror -pipe -Wpointer-arith -Wno-unused-parameter -Wno-unused-function -Wunused-variable -Wunused-value"

AC_CHECK_HEADERS([errno.h fcntl.h stdio.h stdlib.h unistd.h sys/uio.h])
AC_CHECK_HEADERS([sys/select.h sys/socket.h sys/ioctl.h sys/time.h])
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h])

AX_LIBEVENT

AC_SUBST(AX_CPPFLAGS)

AC_CONFIG_FILES([Makefile
                 src/Makefile test/Makefile])

AC_OUTPUT
