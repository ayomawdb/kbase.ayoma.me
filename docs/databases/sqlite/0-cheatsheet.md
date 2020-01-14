# Cheatsheet

Dump entire database:

```
sqlite3 some.db .schema > schema.sql
sqlite3 some.db .dump > dump.sql
grep -vx -f schema.sql dump.sql > data.sql
```

Dump into CSV

```
.mode csv
-- use '.separator SOME_STRING' for something other than a comma.
.headers on
.out file.csv
select * from MyTable;
```

Insert into SQL:

```
.mode insert <target_table_name>
.out file.sql
select * from MyTable;
```
