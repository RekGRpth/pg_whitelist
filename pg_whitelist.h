#ifndef PG_WHITELIST_H
#define PG_WHITELIST_H

/* Registers a PGC_SUSET string GUC named guc_name holding a comma-separated
 * list of file:// and http(s):// prefixes. Call once, from _PG_init(). Since
 * the GUC context is PGC_SUSET, only a superuser can set it -- including via
 * ALTER ROLE ... SET -- so a role cannot loosen its own scope with a plain
 * SET. */
void pg_whitelist_init(const char *guc_name);

/* Call BEFORE resolving fileurl (e.g. before htmldoc's file_find(), which
 * performs the actual network request for an http(s) URL): raises ERROR if
 * fileurl is an http(s) URL not permitted by the GUC registered with
 * pg_whitelist_init(), so a disallowed host is rejected before it's ever
 * contacted. No-op if fileurl is not an http(s) URL -- see
 * pg_whitelist_check_local() for that case -- or if the GUC is empty/unset. */
void pg_whitelist_check_url(const char *fileurl);

/* Call AFTER fileurl has been resolved to an existing local path (realname),
 * for the non-URL case: raises ERROR if realname is not permitted by the
 * GUC. realname is canonicalized with realpath() before comparison so a
 * whitelisted directory can't be escaped via "..". No-op if fileurl is an
 * http(s) URL (already handled by pg_whitelist_check_url()) or if the GUC is
 * empty/unset. */
void pg_whitelist_check_local(const char *fileurl, const char *realname);

#endif
