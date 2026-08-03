#include <postgres.h>

#include <ctype.h>
#include <limits.h>
#include <utils/guc.h>

#include "pg_whitelist.h"

static char *pg_whitelist_value = NULL;

void pg_whitelist_init(const char *guc_name) {
    DefineCustomStringVariable(guc_name, "Comma-separated file:// and http(s):// prefixes that may be accessed. Empty/unset allows anything.", NULL, &pg_whitelist_value, NULL, PGC_SUSET, 0, NULL, NULL, NULL);
}

static void pg_whitelist_deny(const char *fileurl) {
    ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied to access \"%s\"", fileurl), errdetail("whitelist does not permit this file or URL for the current role.")));
}

/* Entries are comma-separated: "file:///dir/" (trailing slash) allows
 * anything under that directory, "file:///dir/file" allows only that exact
 * file, "https://host/path" allows any URL with that prefix. */
void pg_whitelist_check_url(const char *fileurl, bool privileged) {
    char *list, *entry, *saveptr;
    size_t len;
    bool allowed = false;
    if (strncmp(fileurl, "http://", 7) && strncmp(fileurl, "https://", 8)) return;
    if (!pg_whitelist_value || !pg_whitelist_value[0]) {
        if (privileged) return;
        pg_whitelist_deny(fileurl);
    }
    list = pstrdup(pg_whitelist_value);
    for (entry = strtok_r(list, ",", &saveptr); entry && !allowed; entry = strtok_r(NULL, ",", &saveptr)) {
        while (isspace((unsigned char)*entry)) entry++;
        len = strlen(entry);
        while (len > 0 && isspace((unsigned char)entry[len - 1])) entry[--len] = '\0';
        if ((!strncmp(entry, "http://", 7) || !strncmp(entry, "https://", 8)) && !strncmp(fileurl, entry, strlen(entry))) allowed = true;
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
    if (!strncmp(fileurl, "http://", 7) || !strncmp(fileurl, "https://", 8)) return;
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
