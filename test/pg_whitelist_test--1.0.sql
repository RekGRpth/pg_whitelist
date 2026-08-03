CREATE FUNCTION pg_whitelist_test_check(fileurl text, realname text) RETURNS boolean AS 'MODULE_PATHNAME' LANGUAGE C STRICT;
