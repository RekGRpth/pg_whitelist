#include <postgres.h>

#include <ctype.h>
#include <limits.h>
#include <utils/guc.h>

#include "pg_whitelist.h"

static char *pg_whitelist_value = NULL;

void pg_whitelist_init(const char *guc_name) {
    DefineCustomStringVariable(guc_name, "Comma-separated file:// and http(s):// prefixes that may be accessed.", "For a privileged caller a non-empty list narrows access and an empty/unset one allows anything; for any other caller the list is the only grant and an empty/unset one denies everything.", &pg_whitelist_value, NULL, PGC_SUSET, 0, NULL, NULL, NULL);
}

void pg_whitelist_deny(const char *fileurl) {
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
 * evil.net. pg_whitelist_allows_url() already strips that userinfo (see
 * pg_whitelist_drop_userinfo()), so this only still catches a URL with more
 * than one such '@'. */
static bool pg_whitelist_url_prefix(const char *fileurl, const char *entry) {
    size_t len = strlen(entry);
    const char *rest = fileurl + len;
    if (strncmp(fileurl, entry, len)) return false;
    if (len > 0 && entry[len - 1] == '/') return true;
    if (*rest != '\0' && *rest != '/' && *rest != '?' && *rest != '#') return false;
    if (!strchr(strstr(entry, "://") + 3, '/') && rest[strcspn(rest, "@/")] == '@') return false;
    return true;
}

/* Drop userinfo -- everything up to an '@' that comes before the first '/'
 * after "scheme://" -- from url, in place, the way libcups's httpSeparateURI()
 * tells it from the host. What's left names the host the request actually
 * goes to, which is all an entry is about: libcups sends the userinfo as
 * credentials, htmldoc's file-access callback reports every request without
 * it, and a user name in either the URL or an entry doesn't change where the
 * request connects. */
static void pg_whitelist_drop_userinfo(char *url) {
    char *auth, *at;
    if (!(auth = strstr(url, "://"))) return;
    auth += 3;
    at = auth + strcspn(auth, "@/");
    if (*at == '@') memmove(auth, at + 1, strlen(at + 1) + 1);
}

/* Drop a default port -- ":80" for http, ":443" for https -- from the end of
 * url's authority, in place, so "https://host:443/x" and "https://host/x"
 * compare equal. libcups's httpAssembleURI() always spells the port out, so a
 * URL rebuilt by it (as htmldoc's file-access callback reports every request)
 * would otherwise never match an entry written the usual way. */
static void pg_whitelist_drop_default_port(char *url) {
    char *auth, *end, *colon;
    if (!(auth = strstr(url, "://"))) return;
    auth += 3;
    end = auth + strcspn(auth, "/?#");
    for (colon = end; colon > auth && isdigit((unsigned char)colon[-1]); colon--);
    if (colon == end || colon == auth || colon[-1] != ':') return;
    colon--;
    if ((!strncmp(url, "http://", 7) && end - colon == 3 && !strncmp(colon, ":80", 3)) || (!strncmp(url, "https://", 8) && end - colon == 4 && !strncmp(colon, ":443", 4))) memmove(colon, end, strlen(end) + 1);
}

/* Percent-decode everything after url's authority, in place, the way
 * libcups's httpSeparateURI() decodes it before sending: libcups re-encodes
 * only what it must, so "%7E" goes out as "~", "%2F" as "/" and "%3F" as a
 * real "?". Comparing decoded paths makes an entry match however either side
 * happened to spell them. "%00" is left alone, since libcups stops at it. */
static void pg_whitelist_decode_resource(char *url) {
    char *auth, *p, *q;
    if (!(auth = strstr(url, "://"))) return;
    auth += 3;
    for (p = q = auth + strcspn(auth, "/?#"); *p; p++) {
        if (*p == '%' && isxdigit((unsigned char)p[1]) && isxdigit((unsigned char)p[2]) && (p[1] != '0' || p[2] != '0')) {
            char hex[3] = {p[1], p[2], '\0'};
            *q++ = (char)strtol(hex, NULL, 16);
            p += 2;
        } else *q++ = *p;
    }
    *q = '\0';
}

/* Whether url's path -- already percent-decoded, see
 * pg_whitelist_decode_resource() -- has a "." or ".." segment. A server that
 * resolves those lets "https://host/dir/../x" out of an entry for
 * "https://host/dir/", so such a URL may not match an entry with a path below
 * the root (see pg_whitelist_allows_url()). The query isn't part of the path
 * and isn't looked at; a "#" is, though, since libcups sends it as is -- one
 * decoded from "%23" in particular -- and some servers take it literally and
 * resolve dot segments after it. */
static bool pg_whitelist_has_dot_segment(const char *url) {
    const char *auth, *seg, *end;
    size_t len;
    if (!(auth = strstr(url, "://"))) return false;
    auth += 3;
    seg = auth + strcspn(auth, "/?#");
    if (*seg != '/') return false;
    end = seg + strcspn(seg, "?");
    for (; seg && seg < end; seg = memchr(seg, '/', end - seg)) {
        len = strcspn(++seg, "/?");
        if ((len == 1 && seg[0] == '.') || (len == 2 && seg[0] == '.' && seg[1] == '.')) return true;
    }
    return false;
}

/* Whether entry names a path below the root, i.e. something a dot segment
 * could climb out of. "https://host" and "https://host/" don't. */
static bool pg_whitelist_entry_has_path(const char *entry) {
    const char *slash = strchr(strstr(entry, "://") + 3, '/');
    return slash && slash[1];
}

/* Entries are comma-separated: "file:///dir/" (trailing slash) allows
 * anything under that directory, "file:///dir/file" allows only that exact
 * file, "https://host/path" allows any URL with that prefix, matched up to a
 * path segment boundary (see pg_whitelist_url_prefix()). A scheme-relative
 * "//host/..." fileurl never matches an entry (entries always carry an
 * explicit scheme), so only a privileged caller with no whitelist may use
 * one. Userinfo and a default port are ignored and paths compared
 * percent-decoded, on both sides (see pg_whitelist_drop_userinfo(),
 * pg_whitelist_drop_default_port() and pg_whitelist_decode_resource()), and a
 * URL with a dot segment in its path never matches an entry with a path below
 * the root (see pg_whitelist_has_dot_segment()). */
bool pg_whitelist_allows_url(const char *fileurl, bool privileged) {
    char *list, *entry, *saveptr, *url;
    size_t len;
    bool allowed = false, dotted;
    if (!pg_whitelist_is_url(fileurl)) return true;
    if (!pg_whitelist_value || !pg_whitelist_value[0]) return privileged;
    url = pstrdup(fileurl);
    pg_whitelist_drop_userinfo(url);
    pg_whitelist_drop_default_port(url);
    pg_whitelist_decode_resource(url);
    dotted = pg_whitelist_has_dot_segment(url);
    list = pstrdup(pg_whitelist_value);
    for (entry = strtok_r(list, ",", &saveptr); entry && !allowed; entry = strtok_r(NULL, ",", &saveptr)) {
        while (isspace((unsigned char)*entry)) entry++;
        len = strlen(entry);
        while (len > 0 && isspace((unsigned char)entry[len - 1])) entry[--len] = '\0';
        pg_whitelist_drop_userinfo(entry);
        pg_whitelist_drop_default_port(entry);
        pg_whitelist_decode_resource(entry);
        if (strncmp(entry, "http://", 7) && strncmp(entry, "https://", 8)) continue;
        if (dotted && pg_whitelist_entry_has_path(entry)) continue;
        if (pg_whitelist_url_prefix(url, entry)) allowed = true;
    }
    pfree(list);
    pfree(url);
    return allowed;
}

void pg_whitelist_check_url(const char *fileurl, bool privileged) {
    if (!pg_whitelist_allows_url(fileurl, privileged)) pg_whitelist_deny(fileurl);
}

bool pg_whitelist_allows_local(const char *fileurl, const char *realname, bool privileged) {
    char resolved[PATH_MAX];
    char resolved_entry[PATH_MAX];
    char *list, *entry, *saveptr;
    size_t len;
    bool allowed = false;
    if (pg_whitelist_is_url(fileurl)) return true;
    if (!pg_whitelist_value || !pg_whitelist_value[0]) return privileged;
    if (!realpath(realname, resolved)) return false;
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
    return allowed;
}

void pg_whitelist_check_local(const char *fileurl, const char *realname, bool privileged) {
    if (!pg_whitelist_allows_local(fileurl, realname, privileged)) pg_whitelist_deny(fileurl);
}
