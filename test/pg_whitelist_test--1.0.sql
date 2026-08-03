CREATE FUNCTION pg_whitelist_test_check_url(fileurl text) RETURNS boolean AS 'MODULE_PATHNAME' LANGUAGE C STRICT;
CREATE FUNCTION pg_whitelist_test_check_local(fileurl text, realname text) RETURNS boolean AS 'MODULE_PATHNAME' LANGUAGE C STRICT;
