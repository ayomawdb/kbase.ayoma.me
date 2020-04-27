## Docker

### General Commands 

- Mount host file system into a container and run: `docker run --rm -ti -v /:/hostOs <image> sh`
- Auto remove container when exit: `docker run --rm`
- List all images: `docker images --all`

### Enumeration 

Check presence of docker:
```
/.dockerenv
```

## Tools 

### binctr

- Create fully static, including rootfs embedded, binaries that pop you directly into a container.
- Can be run by an unprivileged user.
- <https://github.com/genuinetools/binctr>
- <https://blog.ropnop.com/docker-for-pentesters/>

## CVE-2019-5736

- <https://kubernetes.io/blog/2019/02/11/runc-and-cve-2019-5736/>
- <https://gist.github.com/singe/0ad4078848d85dc0d03f9f9013796e45>

## New References

- [Security analysis of Docker containers in a production environment](https://brage.bibsys.no/xmlui/bitstream/handle/11250/2451326/17303_FULLTEXT.pdf)
- [Cryptojacking invades cloud. How modern containerization trend is exploited by attackers](https://kromtech.com/blog/security-center/cryptojacking-invades-cloud-how-modern-containerization-trend-is-exploited-by-attackers)

