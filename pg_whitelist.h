#ifndef PG_WHITELIST_H
#define PG_WHITELIST_H

/* Registers a PGC_SUSET string GUC named guc_name holding a comma-separated
 * list of file:// and http(s):// prefixes. Call once, from _PG_init(). Since
 * the GUC context is PGC_SUSET, only a superuser can set it -- including via
 * ALTER ROLE ... SET -- so a role cannot loosen its own scope with a plain
 * SET. */
void pg_whitelist_init(const char *guc_name);

/* Raises ERROR if fileurl (or, for local paths, realname) is not permitted
 * by the GUC registered with pg_whitelist_init(). realname must be an
 * existing local path when fileurl is not an http(s) URL, since it is
 * resolved with realpath() before comparison so a whitelisted directory
 * can't be escaped via "..". A no-op if the GUC is empty/unset. */
void pg_whitelist_check(const char *fileurl, const char *realname);

#endif
