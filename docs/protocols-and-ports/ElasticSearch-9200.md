# Interesting APIs

Description                         | URL
:---------------------------------- | :--------------------------------------------------------------
Config information, OS, JVM version | `curl -XGET http://<ip>:9200/_nodes?pretty=true`
Shutdown                            | `curl -XPOST http://<ip>:9200/_cluster/nodes/_master/_shutdown`
Dump data                           | `curl "http://<ip>:9200/_search?size=10000&pretty=true"`
Snapshots                           | `_snapshot`

# Hardening

`elasticsearch.yml` - to prevent dynamic scripting:

```
script.disable_dynamic: true
```

- [https://medium.com/@bromiley/exploiting-elasticsearch-c83825708ce1](mailto:https://medium.com/@bromiley/exploiting-elasticsearch-c83825708ce1)
