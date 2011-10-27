#include "kdc_locl.h"

#if HAVE_DB1
#if defined(HAVE_DB_185_H)
#include <db_185.h>
#elif defined(HAVE_DB_H)
#include <db.h>
#endif
#endif /* HAVE_DB1 */

int
main(int argc, char **argv)
{
#if HAVE_DB1
    DB      *db;
    DBT      key;
    DBT      val;
    DBTYPE   dbtypes[3] = { DB_HASH, DB_BTREE, DB_RECNO };
    size_t   i;
    int      ret;

    if (argc != 2 && argc != 3) {
	fprintf(stderr, "Usage: %s db [key]\n", argv[0]);
	return 1;
    }

    /* Try every possible DB type */
    for (i = 0; i < 3; i++) {
	db = dbopen(argv[1], O_RDONLY, 0, dbtypes[i], NULL);
	if (db)
	    break;
    }
    if (!db) {
	perror("dbopen");
	return 1;
    }

    if (argc == 3) {
	/* Lookup one key */
	key.data = argv[2];
	key.size = strlen(argv[2]);
	ret = db->get(db, &key, &val, 0);
	switch (ret) {
	case 0:
	    printf("%.*s\n", val.size, (char *)val.data);
	    break;
	case 1:
	    printf("key not found\n");
	    break;
	default:
	    break;
	}
    } else {
	/* Else dump the DB */
	for (ret = db->seq(db, &key, &val, R_FIRST);
	     ret == 0;
	     ret = db->seq(db, &key, &val, R_NEXT)) {
	    printf("'%.*s' = '%.*s'\n",
		   key.size, (char *)key.data,
		   val.size, (char *)val.data);
	}
    }

    if (ret == -1) {
	perror("Error: reading database");
	ret = 1;
    }

    db->close(db);
    return ret;
#else
    fprintf(stderr,
	    "This program is not supported because you don't have DB1 "
	    "(or MIT db2) support\n");
    return 1;
#endif /* HAVE_DB1 */
}
