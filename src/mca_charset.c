
	/* $Id: mca_charset.c,v 1.2 2008/01/30 23:47:42 anight Exp $ */
	/* (c) Andrei Nigmatulin, 2007 */

#include <string.h>

#include <mca.h>
#include <mca_private.h>

#define MCA_DEFAULT_CHARSET 8

extern const struct mca_charset all_charsets[256];

const struct mca_charset *mca_charset_get_by_csname(char *csname)
{
	const struct mca_charset *cs;

	for (cs = &all_charsets[0]; cs < &all_charsets[256]; ++cs) {
		if (cs->csname && !strcasecmp(cs->csname, csname)) return cs;
	}

	return 0;
}

const struct mca_charset *mca_charset_get_by_name(char *name)
{
	const struct mca_charset *cs;

	for (cs = &all_charsets[0]; cs < &all_charsets[256]; ++cs) {
		if (cs->name && !strcasecmp(cs->name, name)) return cs;
	}

	return 0;
}

const struct mca_charset *mca_charset_get_default()
{
	return &all_charsets[MCA_DEFAULT_CHARSET];
}
