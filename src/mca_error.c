
	/* $Id: mca_error.c,v 1.2 2008/05/12 12:49:38 anight Exp $ */
	/* (c) Andrei Nigmatulin, 2007 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <mca.h>
#include <mca_private.h>

void mca_set_error(mca *m, int use_errno, char *fmt, ...)
{
	const size_t buf_size = sizeof(m->last_error);
	char *buf = m->last_error;
	va_list args;
	size_t len = 0;
	int truncated = 0;
	int saved_errno;

	saved_errno = errno;

	va_start(args, fmt);

	len = vsnprintf(buf + len, buf_size - len, fmt, args);

	va_end(args);

	if (len >= buf_size) {
		truncated = 1;
	}

	if (!truncated) {
		if (use_errno) {
			len += snprintf(buf + len, buf_size - len, ": %s (%d)", strerror(saved_errno), saved_errno);
			if (len >= buf_size) {
				truncated = 1;
			}
		}
	}

	if (truncated) {
		memcpy(buf + buf_size - sizeof("..."), "...", sizeof("...") - 1);
		len = buf_size - 1;
	}

	buf[len++] = '\0';

	errno = saved_errno;
}
