#include <postgres.h>

#include <ctype.h>
#include <limits.h>
#include <utils/guc.h>

#include "pg_whitelist.h"

static char *pg_whitelist_value = NULL;

void pg_whitelist_init(const char *guc_name) {
    DefineCustomStringVariable(guc_name, "Comma-separated file:// and http(s):// prefixes that may be accessed.", "For a privileged caller a non-empty list narrows access and an empty/unset one allows anything; for any other caller the list is the only grant and an empty/unset one denies everything.", &pg_whitelist_value, NULL, PGC_SUSET, 0, NULL, NULL, NULL);
}

static void pg_whitelist_deny(const char *fileurl) {
    ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied to access \"%s\"", fileurl), errdetail("whitelist does not permit this file or URL for the current role.")));
}

/* Whether htmldoc's file_find() would fetch s over the network: it treats
 * anything starting with "http:", "https:" or a scheme-relative "//" as a URL
 * (see file_find()/file_find_check() in htmldoc's file.c). A "//host/..."
 * fileurl is therefore a URL too -- missing it here would let it skip
 * pg_whitelist_check_url() (and pass pg_whitelist_check_local() only after the
 * request was already made). */
static bool pg_whitelist_is_url(const char *s) {
    return !strncmp(s, "http:", 5) || !strncmp(s, "https:", 6) || !strncmp(s, "//", 2);
}

/* fileurl starts with entry, and not just textually: unless entry ends in '/',
 * the match must end at a URL delimiter, so "https://host" doesn't match
 * "https://host.evil.net/" or "https://host@evil.net/", nor "https://host/api"
 * match "https://host/api2". And if entry names only a host (no path), the
 * rest of fileurl's authority -- up to its first '/' -- must not contain '@':
 * libcups's httpSeparateURI() (which htmldoc fetches through) takes
 * everything before an '@' that precedes the first '/' as userinfo, so
 * "https://host?@evil.net/" or "https://host#@evil.net/" would connect to
 * evil.net. */
static bool pg_whitelist_url_prefix(const char *fileurl, const char *entry) {
    size_t len = strlen(entry);
    const char *rest = fileurl + len;
    if (strncmp(fileurl, entry, len)) return false;
    if (len > 0 && entry[len - 1] == '/') return true;
    if (*rest != '\0' && *rest != '/' && *rest != '?' && *rest != '#') return false;
    if (!strchr(strstr(entry, "://") + 3, '/') && rest[strcspn(rest, "@/")] == '@') return false;
    return true;
}

/* Entries are comma-separated: "file:///dir/" (trailing slash) allows
 * anything under that directory, "file:///dir/file" allows only that exact
 * file, "https://host/path" allows any URL with that prefix, matched up to a
 * path segment boundary (see pg_whitelist_url_prefix()). A scheme-relative
 * "//host/..." fileurl never matches an entry (entries always carry an
 * explicit scheme), so only a privileged caller with no whitelist may use
 * one. */
void pg_whitelist_check_url(const char *fileurl, bool privileged) {
    char *list, *entry, *saveptr;
    size_t len;
    bool allowed = false;
    if (!pg_whitelist_is_url(fileurl)) return;
    if (!pg_whitelist_value || !pg_whitelist_value[0]) {
        if (privileged) return;
        pg_whitelist_deny(fileurl);
    }
    list = pstrdup(pg_whitelist_value);
    for (entry = strtok_r(list, ",", &saveptr); entry && !allowed; entry = strtok_r(NULL, ",", &saveptr)) {
        while (isspace((unsigned char)*entry)) entry++;
        len = strlen(entry);
        while (len > 0 && isspace((unsigned char)entry[len - 1])) entry[--len] = '\0';
        if ((!strncmp(entry, "http://", 7) || !strncmp(entry, "https://", 8)) && pg_whitelist_url_prefix(fileurl, entry)) allowed = true;
    }
    pfree(list);
    if (!allowed) pg_whitelist_deny(fileurl);
}

void pg_whitelist_check_local(const char *fileurl, const char *realname, bool privileged) {
    char resolved[PATH_MAX];
    char resolved_entry[PATH_MAX];
    char *list, *entry, *saveptr;
    size_t len;
    bool allowed = false;
    if (pg_whitelist_is_url(fileurl)) return;
    if (!pg_whitelist_value || !pg_whitelist_value[0]) {
        if (privileged) return;
        pg_whitelist_deny(fileurl);
    }
    if (!realpath(realname, resolved)) ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("!realpath(\"%s\")", realname)));
    list = pstrdup(pg_whitelist_value);
    for (entry = strtok_r(list, ",", &saveptr); entry && !allowed; entry = strtok_r(NULL, ",", &saveptr)) {
        while (isspace((unsigned char)*entry)) entry++;
        len = strlen(entry);
        while (len > 0 && isspace((unsigned char)entry[len - 1])) entry[--len] = '\0';
        if (!strncmp(entry, "file://", 7)) {
            const char *entry_path = entry + 7;
            size_t plen = strlen(entry_path);
            if (plen > 0 && entry_path[plen - 1] == '/') {
                if (!strncmp(resolved, entry_path, plen)) allowed = true;
            } else if (!strcmp(resolved, realpath(entry_path, resolved_entry) ? resolved_entry : entry_path)) allowed = true;
        }
    }
    pfree(list);
    if (!allowed) pg_whitelist_deny(fileurl);
}
