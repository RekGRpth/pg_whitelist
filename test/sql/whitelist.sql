CREATE EXTENSION pg_whitelist_test;

-- privileged=true, no whitelist configured: always allowed.
SELECT pg_whitelist_test_check_url('https://example.com/anything', true);

-- privileged=false, no whitelist configured: always denied -- whitelist is
-- the caller's only possible grant, and there isn't one.
SELECT pg_whitelist_test_check_url('https://example.com/anything', false);

SET pg_whitelist_test.whitelist = 'https://good.example.com/';

-- privileged=true: whitelist narrows -- matches pass through, non-matches
-- are denied even though the caller would otherwise be authorized.
SELECT pg_whitelist_test_check_url('https://good.example.com/page', true);
SELECT pg_whitelist_test_check_url('https://evil.example.com/page', true);

-- privileged=false: whitelist is the caller's sole grant -- same
-- allow/deny split as above, but for the opposite reason.
SELECT pg_whitelist_test_check_url('https://good.example.com/page', false);
SELECT pg_whitelist_test_check_url('https://evil.example.com/page', false);

-- An entry without a trailing slash still only matches up to a URL
-- delimiter ('/', '?', '#' or the end), not any textual prefix: another
-- host that merely starts with the same name, userinfo pointing elsewhere,
-- another port or a longer path segment are all denied. So is an '@' after
-- a '?' or '#' delimiter but before the first '/': libcups would take
-- everything before it as userinfo and connect to the host after it. Once
-- the entry itself contains a path, the host is already fixed and a later
-- '@' is harmless.
SET pg_whitelist_test.whitelist = 'https://good.example.com,https://other.example.com/api';
SELECT pg_whitelist_test_check_url('https://good.example.com', false);
SELECT pg_whitelist_test_check_url('https://good.example.com/page', false);
SELECT pg_whitelist_test_check_url('https://good.example.com?q=1', false);
SELECT pg_whitelist_test_check_url('https://good.example.com#frag', false);
SELECT pg_whitelist_test_check_url('https://good.example.com?@evil.net/page', false);
SELECT pg_whitelist_test_check_url('https://good.example.com#@evil.net/page', false);
SELECT pg_whitelist_test_check_url('https://good.example.com?q=1@evil.net/page', false);
SELECT pg_whitelist_test_check_url('https://good.example.com?q=1/@not-a-host', false);
SELECT pg_whitelist_test_check_url('https://good.example.com.evil.net/page', false);
SELECT pg_whitelist_test_check_url('https://good.example.com@evil.net/page', false);
SELECT pg_whitelist_test_check_url('https://good.example.com:8443/page', false);
SELECT pg_whitelist_test_check_url('https://other.example.com/api/v1', false);
SELECT pg_whitelist_test_check_url('https://other.example.com/api2', false);
SELECT pg_whitelist_test_check_url('https://other.example.com/api?@evil.net/page', false);
SET pg_whitelist_test.whitelist = 'https://good.example.com/';

-- A default port is the same URL spelled differently, on either side: libcups
-- spells it out in every URL it rebuilds, so "https://host/" must match
-- "https://host:443/..." and vice versa. Any other port, including the other
-- scheme's default, is still a different URL.
SELECT pg_whitelist_test_check_url('https://good.example.com:443/page', false);
SELECT pg_whitelist_test_check_url('https://good.example.com:80/page', false);
SELECT pg_whitelist_test_check_url('https://good.example.com:4430/page', false);
SET pg_whitelist_test.whitelist = 'https://good.example.com:443/,http://plain.example.com';
SELECT pg_whitelist_test_check_url('https://good.example.com/page', false);
SELECT pg_whitelist_test_check_url('http://plain.example.com:80/page', false);
SELECT pg_whitelist_test_check_url('http://plain.example.com:80?@evil.net/page', false);
SELECT pg_whitelist_test_check_url('http://plain.example.com:8080/page', false);
SET pg_whitelist_test.whitelist = 'https://good.example.com/';

-- A user name and password aren't part of the host: libcups takes everything
-- before an '@' ahead of the first '/' as userinfo, sends it as credentials
-- and connects to what follows, and htmldoc's file-access callback reports
-- each request without it. So it's ignored on both sides and only the host is
-- compared -- including when the userinfo is dressed up as a permitted host.
SET pg_whitelist_test.whitelist = 'https://good.example.com/,https://user:pass@other.example.com/';
SELECT pg_whitelist_test_check_url('https://user:pass@good.example.com/page', false);
SELECT pg_whitelist_test_check_url('https://other.example.com/page', false);
SELECT pg_whitelist_test_check_url('https://someone@other.example.com/page', false);
SELECT pg_whitelist_test_check_url('https://good.example.com:pass@evil.net/page', false);
SET pg_whitelist_test.whitelist = 'https://good.example.com/';

-- Paths are compared percent-decoded, on both sides: libcups decodes a URL's
-- path before sending it, re-encoding only what it must, and htmldoc's
-- file-access callback reports it that way -- so "%7E" and "~" are the same
-- path however either side spells it, and a decoded "%2F" is a real "/".
-- Decoding happens once, as libcups does it: "%252E" is a literal "%2E". A
-- decoded "%23" is a "#" libcups sends as is, not the start of a fragment, so
-- dot segments after it still count.
SET pg_whitelist_test.whitelist = 'https://good.example.com/%7Euser/,https://other.example.com/~staff/';
SELECT pg_whitelist_test_check_url('https://good.example.com/~user/a.html', false);
SELECT pg_whitelist_test_check_url('https://good.example.com/%7euser/a.html', false);
SELECT pg_whitelist_test_check_url('https://other.example.com/%7Estaff/a.html', false);
SELECT pg_whitelist_test_check_url('https://other.example.com/%7Estaffer/a.html', false);
SELECT pg_whitelist_test_check_url('https://other.example.com/~staff%2F..%2Fsecret.html', false);
SELECT pg_whitelist_test_check_url('https://other.example.com/~staff/%252E%252E/a.html', false);
SELECT pg_whitelist_test_check_url('https://other.example.com/~staff/%23/../secret.html', false);
SET pg_whitelist_test.whitelist = 'https://good.example.com/';

-- An entry with a path confines to that path only if dot segments can't climb
-- out of it: libcups sends them as written (decoding %2E and %2F first), and
-- servers commonly resolve them. So a URL with a "." or ".." segment in its
-- path never matches an entry below the root. Dots that aren't a whole
-- segment, and dots in the query, are fine; a root entry has nothing to climb
-- out of and is unaffected.
SET pg_whitelist_test.whitelist = 'https://good.example.com/reports/';
SELECT pg_whitelist_test_check_url('https://good.example.com/reports/a.html', false);
SELECT pg_whitelist_test_check_url('https://good.example.com/reports/../secret.html', false);
SELECT pg_whitelist_test_check_url('https://good.example.com/reports/%2E%2E/secret.html', false);
SELECT pg_whitelist_test_check_url('https://good.example.com/reports/..%2Fsecret.html', false);
SELECT pg_whitelist_test_check_url('https://good.example.com/reports/sub/..', false);
SELECT pg_whitelist_test_check_url('https://good.example.com/reports/./a.html', false);
SELECT pg_whitelist_test_check_url('https://good.example.com/reports/..a.html', false);
SELECT pg_whitelist_test_check_url('https://good.example.com/reports/a.html?next=../secret.html', false);
SET pg_whitelist_test.whitelist = 'https://good.example.com/';
SELECT pg_whitelist_test_check_url('https://good.example.com/reports/../secret.html', false);

-- A scheme-relative "//host/..." is fetched over http by htmldoc, so it is a
-- URL too, not a local path: it never matches an entry (entries always carry
-- a scheme), so only privileged with no whitelist may use it.
SELECT pg_whitelist_test_check_url('//good.example.com/page', true);
SELECT pg_whitelist_test_check_url('//good.example.com/page', false);
SELECT pg_whitelist_test_check_url('//evil.example.com/page', true);
SET pg_whitelist_test.whitelist = '';
SELECT pg_whitelist_test_check_url('//evil.example.com/page', true);
SELECT pg_whitelist_test_check_url('//evil.example.com/page', false);
SET pg_whitelist_test.whitelist = 'https://good.example.com/';

-- Non-URL input is not this function's concern -- always a no-op pass,
-- regardless of privileged.
SELECT pg_whitelist_test_check_url('/etc/passwd', true);
SELECT pg_whitelist_test_check_url('/etc/passwd', false);

COPY (SELECT '') TO '/tmp/pg_whitelist_test_allowed.txt';

SET pg_whitelist_test.whitelist = '';

-- privileged=true, no whitelist configured: always allowed.
SELECT pg_whitelist_test_check_local('/tmp/pg_whitelist_test_allowed.txt', '/tmp/pg_whitelist_test_allowed.txt', true);

-- privileged=false, no whitelist configured: always denied.
SELECT pg_whitelist_test_check_local('/tmp/pg_whitelist_test_allowed.txt', '/tmp/pg_whitelist_test_allowed.txt', false);

SET pg_whitelist_test.whitelist = 'file:///tmp/pg_whitelist_test_allowed.txt';
SELECT pg_whitelist_test_check_local('/tmp/pg_whitelist_test_allowed.txt', '/tmp/pg_whitelist_test_allowed.txt', true);
SELECT pg_whitelist_test_check_local('/etc/passwd', '/etc/passwd', true);
SELECT pg_whitelist_test_check_local('/tmp/pg_whitelist_test_allowed.txt', '/tmp/pg_whitelist_test_allowed.txt', false);
SELECT pg_whitelist_test_check_local('/etc/passwd', '/etc/passwd', false);

-- URL input is not this function's concern -- always a no-op pass regardless
-- of whitelist contents or privileged.
SELECT pg_whitelist_test_check_local('https://evil.example.com/page', '/tmp/pg_whitelist_test_allowed.txt', true);
SELECT pg_whitelist_test_check_local('https://evil.example.com/page', '/tmp/pg_whitelist_test_allowed.txt', false);
SELECT pg_whitelist_test_check_local('//evil.example.com/page', '/tmp/pg_whitelist_test_allowed.txt', false);

-- Directory entry (trailing slash): anything under it is allowed, but ".."
-- can't be used to climb back out, since the resolved path is
-- realpath()-canonicalized before comparison.
SET pg_whitelist_test.whitelist = 'file:///tmp/';
SELECT pg_whitelist_test_check_local('/tmp/pg_whitelist_test_allowed.txt', '/tmp/pg_whitelist_test_allowed.txt', false);
SELECT pg_whitelist_test_check_local('/tmp/../etc/passwd', '/tmp/../etc/passwd', false);
