CREATE EXTENSION pg_whitelist_test;

SELECT pg_whitelist_test_check_url('https://example.com/anything');

SET pg_whitelist_test.whitelist = 'https://good.example.com/';
SELECT pg_whitelist_test_check_url('https://good.example.com/page');
SELECT pg_whitelist_test_check_url('https://evil.example.com/page');
SELECT pg_whitelist_test_check_url('/etc/passwd');

COPY (SELECT '') TO '/tmp/pg_whitelist_test_allowed.txt';
SET pg_whitelist_test.whitelist = 'file:///tmp/pg_whitelist_test_allowed.txt';
SELECT pg_whitelist_test_check_local('/tmp/pg_whitelist_test_allowed.txt', '/tmp/pg_whitelist_test_allowed.txt');
SELECT pg_whitelist_test_check_local('/etc/passwd', '/etc/passwd');
SELECT pg_whitelist_test_check_local('https://evil.example.com/page', '/tmp/pg_whitelist_test_allowed.txt');

SET pg_whitelist_test.whitelist = 'file:///tmp/';
SELECT pg_whitelist_test_check_local('/tmp/pg_whitelist_test_allowed.txt', '/tmp/pg_whitelist_test_allowed.txt');
SELECT pg_whitelist_test_check_local('/tmp/../etc/passwd', '/tmp/../etc/passwd');
