CREATE FUNCTION pg_whitelist_test_check_url(fileurl text, privileged boolean) RETURNS boolean AS 'MODULE_PATHNAME' LANGUAGE C STRICT;
CREATE FUNCTION pg_whitelist_test_check_local(fileurl text, realname text, privileged boolean) RETURNS boolean AS 'MODULE_PATHNAME' LANGUAGE C STRICT;
