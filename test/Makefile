EXTENSION = pg_whitelist_test
MODULE_big = $(EXTENSION)
OBJS = $(EXTENSION).o ../pg_whitelist.o
DATA = $(EXTENSION)--1.0.sql
REGRESS = $(patsubst sql/%.sql,%,$(wildcard sql/*.sql))
PG_CONFIG = pg_config
PGXS = $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
