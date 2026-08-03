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

-- Directory entry (trailing slash): anything under it is allowed, but ".."
-- can't be used to climb back out, since the resolved path is
-- realpath()-canonicalized before comparison.
SET pg_whitelist_test.whitelist = 'file:///tmp/';
SELECT pg_whitelist_test_check_local('/tmp/pg_whitelist_test_allowed.txt', '/tmp/pg_whitelist_test_allowed.txt', false);
SELECT pg_whitelist_test_check_local('/tmp/../etc/passwd', '/tmp/../etc/passwd', false);
