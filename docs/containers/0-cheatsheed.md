# Cheatsheet

## Docker

## General

Mount host file system into a container and run:
```
docker run --rm -ti -v /:/hostOs <image> sh
```

Auto remove container when exit:
```
docker run --rm
```

List all images:
```
docker images --all
```
## Identifying Docker

Presence of files:
```
/.dockerenv
```

