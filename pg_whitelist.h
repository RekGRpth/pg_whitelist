#ifndef PG_WHITELIST_H
#define PG_WHITELIST_H

/* Registers a PGC_SUSET string GUC named guc_name holding a comma-separated
 * list of file:// and http(s):// prefixes. Call once, from _PG_init(). Since
 * the GUC context is PGC_SUSET, only a superuser can set it -- including via
 * ALTER ROLE ... SET -- so a role cannot loosen its own scope with a plain
 * SET. */
void pg_whitelist_init(const char *guc_name);

/* privileged=true: fileurl is allowed unless a non-empty whitelist
 * explicitly excludes it (whitelist narrows an already-authorized caller).
 * privileged=false: fileurl is allowed ONLY if a non-empty whitelist
 * explicitly includes it (whitelist is the caller's sole grant, used in
 * place of whatever privilege would otherwise be required) -- an
 * empty/unset whitelist denies in this case, the opposite of the
 * privileged=true default. Either way, raises ERROR when access isn't
 * permitted.
 *
 * Call pg_whitelist_check_url() BEFORE resolving fileurl (e.g. before
 * htmldoc's file_find(), which performs the actual network request for an
 * http(s) URL), so a disallowed host is rejected before it's ever
 * contacted. No-op if fileurl is not an http(s) URL -- see
 * pg_whitelist_check_local() for that case. */
void pg_whitelist_check_url(const char *fileurl, bool privileged);

/* Call AFTER fileurl has been resolved to an existing local path (realname),
 * for the non-URL case: realname is canonicalized with realpath() before
 * comparison so a whitelisted directory can't be escaped via "..". No-op if
 * fileurl is an http(s) URL (handled by pg_whitelist_check_url() instead). */
void pg_whitelist_check_local(const char *fileurl, const char *realname, bool privileged);

#endif
