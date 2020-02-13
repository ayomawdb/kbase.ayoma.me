redis-cli -h 10.10.10.160
10.10.10.160:6379> dbsize
(integer) 0
(0.51s)
10.10.10.160:6379> CONFIG GET databases
1) "databases"
2) "16"
(0.63s)
10.10.10.160:6379> INFO keyspace
# Keyspace
(0.56s)
10.10.10.160:6379> INFO
