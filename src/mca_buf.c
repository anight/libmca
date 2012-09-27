
	/* $Id: mca_buf.c,v 1.2 2008/01/31 13:20:54 anight Exp $ */
	/* (c) Andrei Nigmatulin, 2007 */

#include <stdlib.h>
#include <stdint.h>

#include <mca.h>
#include <mca_private.h>

#define MCA_INITIAL_BUF 16384

void *mca_alloc_buf(mca *m, size_t s)
{
	size_t real_size;

	if (m->buf_allocated < s) {
		real_size = s < MCA_INITIAL_BUF ? MCA_INITIAL_BUF : s;

		m->buf = realloc(m->buf, real_size);

		if (!m->buf) return 0;

		m->buf_allocated = real_size;
	}

	return m->buf;
}

mca_row *mca_alloc_row()
{
	mca_row *ret;

	ret = malloc(sizeof(*ret));

	return ret;
}
