## Scan for hosts
```
nmap -sn $iprange -oG - | grep Up | cut -d' ' -f2 > network.txt
```

## Port scanning

### TCP Top 1000:
```
nmap -Pn -sC -sV -oA tcp -vv $ip
```

### Quick TCP

```
nmap -sC -sV -vv -oA quick 10.10.10.10
```

### All TCP Ports:

```
nmap -sC -sV -oA all -vv -p- $ip
```

### UDP Top 100:
```
nmap -Pn -sU --top-ports 100 -oA udp -vv $ip
```

#### Quick UDP

```
nmap -sU -sV -vv -oA quick_udp 10.10.10.10
```

## Port Knocking 

```
for x in 7000 8000 9000; do nmap -Pn --host_timeout 201 --max-retries 0 -p $x 10.10.10.10; done
```

