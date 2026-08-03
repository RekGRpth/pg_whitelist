#include <postgres.h>

#include <fmgr.h>
#include <utils/builtins.h>

#include "../pg_whitelist.h"

PG_MODULE_MAGIC;

void _PG_init(void); void _PG_init(void) {
    pg_whitelist_init("pg_whitelist_test.whitelist");
}

PG_FUNCTION_INFO_V1(pg_whitelist_test_check_url);
Datum pg_whitelist_test_check_url(PG_FUNCTION_ARGS) {
    char *fileurl = TextDatumGetCString(PG_GETARG_DATUM(0));
    bool privileged = PG_GETARG_BOOL(1);
    pg_whitelist_check_url(fileurl, privileged);
    pfree(fileurl);
    PG_RETURN_BOOL(true);
}

PG_FUNCTION_INFO_V1(pg_whitelist_test_check_local);
Datum pg_whitelist_test_check_local(PG_FUNCTION_ARGS) {
    char *fileurl = TextDatumGetCString(PG_GETARG_DATUM(0));
    char *realname = TextDatumGetCString(PG_GETARG_DATUM(1));
    bool privileged = PG_GETARG_BOOL(2);
    pg_whitelist_check_local(fileurl, realname, privileged);
    pfree(fileurl);
    pfree(realname);
    PG_RETURN_BOOL(true);
}
