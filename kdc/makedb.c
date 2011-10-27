#include "kdc_locl.h"

#if HAVE_DB1
#if defined(HAVE_DB_185_H)
#include <db_185.h>
#elif defined(HAVE_DB_H)
#include <db.h>
#endif
#endif /* HAVE_DB1 */

int main(int argc, char **argv)
{
#if HAVE_DB1
    DB *db;
    DBT key;
    DBT val;
    FILE *in = stdin;
    int line = 0;
    int fd;
    int ret;
    char buf[1024];
    char *fn;
    char *tmpfn = NULL;

    if (argc != 2 && argc != 3) {
	fprintf(stderr, "Usage: %s db\n", argv[0]);
	fprintf(stderr, "       %s db source-file\n", argv[0]);
	return 1;
    }
    fn = argv[1];

    if (argc == 3) {
	in = fopen(argv[2], "r");
	if (in == NULL) {
	    perror("Could not open source file");
	    return 1;
	}
    }

    if (asprintf(&tmpfn, "%s-XXXXXX", argv[1]) == -1) {
	fprintf(stderr, "THIS SHOULD NOT HAPPEN!\n");
	return 1;
    }

    umask(077);
    fd = mkstemp(tmpfn);
    if (fd == -1) {
	perror("mkstemp");
	return 1;
    }
    close(fd);

    /*
     * O_TRUNC is needed to make DB_HASH happy with the zero-length file
     * created by mkstemp(3)
     */
    db = dbopen(tmpfn, O_RDWR | O_TRUNC, 0600, DB_HASH, NULL);
    if (!db) {
	perror("dbopen");
	goto bail;
    }

    while (fgets(buf, sizeof(buf) - 1, in)) {
	char *cp, *cp2, *cp3;

	line++;

	/* nul-terminate buf */
	cp = strchr(buf, '\n');
	if (!cp) {
	    fprintf(stderr, "Line too long at %d\n", line);
	    goto bail;
	}
	*cp = '\0';

	for (cp = buf; !isspace(*cp) && *cp != '\0'; cp++)
	    ;

	if (*cp == '\0') {
	    fprintf(stderr, "Error: missing value at line %d\n", line);
	    goto bail;
	}
	*cp++ = '\0';

	while (isspace(*cp))
	    cp++;

	if (*cp == '\0') {
	    fprintf(stderr, "Error: zero-length value in line %d\n", line);
	    goto bail;
	}

	/*
	 * Remove trailing whitespace (really? it'd be nice to add an
	 * option not to)
	 */
	for (cp3 = NULL, cp2 = cp; *cp2; cp2++) {
	    if (!isspace(*cp2))
		cp3 = cp2 + 1;
	}
	if (cp3 && isspace(*cp3))
	    *cp3 = '\0';

	key.data = buf;
	key.size = strlen(buf);
	val.data = cp;
	val.size = strlen(cp);

	ret = db->put(db, &key, &val, 0);
	switch (ret) {
	case 0:
	case 1:
	    break;
	default:
	    perror("Error: storing DB entry");
	    goto bail;
	}
    }

    db->close(db);
    if (!feof(in) || ferror(in)) {
	perror("Error: reading input");
	goto bail;
    }

    if (rename(tmpfn, fn)) {
	perror("rename");
	goto bail;
    }

    return 0;

bail:
    if (unlink(tmpfn) == -1)
	perror("unlink");
    return 1;
#else
    fprintf(stderr,
	    "This program is not supported because you don't have DB1 "
	    "(or MIT db2) support\n");
    return 1;
#endif /* HAVE_DB1 */
}

