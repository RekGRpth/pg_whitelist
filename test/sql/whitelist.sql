CREATE EXTENSION pg_whitelist_test;

SELECT pg_whitelist_test_check('https://example.com/anything', '');

SET pg_whitelist_test.whitelist = 'https://good.example.com/';
SELECT pg_whitelist_test_check('https://good.example.com/page', '');
SELECT pg_whitelist_test_check('https://evil.example.com/page', '');

COPY (SELECT '') TO '/tmp/pg_whitelist_test_allowed.txt';
SET pg_whitelist_test.whitelist = 'file:///tmp/pg_whitelist_test_allowed.txt';
SELECT pg_whitelist_test_check('/tmp/pg_whitelist_test_allowed.txt', '/tmp/pg_whitelist_test_allowed.txt');
SELECT pg_whitelist_test_check('/etc/passwd', '/etc/passwd');
