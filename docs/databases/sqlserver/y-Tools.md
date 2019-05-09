# Tools

## SQSH
- [Accessing and Hacking MSSQL from Backtrack Linux](https://www.adampalmer.me/iodigitalsec/2013/08/10/accessing-and-hacking-mssql-from-backtrack-linux/)

```
apt-get install sqsh freetds-bin freetds-common freetds-dev
```

Edit `/etc/freetds/freetds.conf`, and append:

```
[MyServer]
host = 192.168.1.10
port = 1433
tds version = 8.0
```

Optionally edit `~/.sqshrc`:

```
\set username=sa
\set password=password
\set style=vert
```

Run:

```
sqsh -S MyServer
```
```
sqsh -S {system name/IP}:{port num} -U {username} -P {password}
```

List of available databases with:
```
SELECT name FROM master..sysdatabases
go
```

Build from source:
```
$export SYBASE=/usr/local/freetds
$ ./configure
$ make
$ su
# make install
# ls -l /usr/local/bin/sqsh
# ls -l /usr/local/bin/sqsh.bin
```
