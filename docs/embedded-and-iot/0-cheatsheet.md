# Cheetshet

## Cross Compiling

### Compile for MIPS

```
mips-linux-gnu-gcc bindshell.c -o bindshell -static
mips-linux-gnu-strip bindshell
```

## ESP

### Read Flash
```
esptool.py -p /dev/ttyUSB0 -b 460800 read_flash 0 0x200000 flash.bin
```

### Check Device config
```
espefuse.py --port /dev/ttyUSB0 summary
```

## Binwalk

### Display information
```
binwalk -t -vvv example-firmware
```

### Extract
```
binwalk -e -t -vvv example-firmware
```

### Entropy Analysis (identity compression / encryption)
```
binwalk -E example-firmware
```
> http://www.devttys0.com/2013/06/differentiate-encryption-from-compression-using-math/

### Repacking Firmware

```
./extract-firmware.sh example-firmware.bin
./build-formware.sh
```
> https://github.com/rampageX/firmware-mod-kit/wiki


## Busybox

### Command Injection
- https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2010/february/busybox-command-injection/

### Bind a telnet shell to port 9999
```
/bin/busybox telnetd -l/bin/sh -p9999
```

## QMUE

### Run binaries inside a firmware
```
whereis qemu-mips-static
cp /etc/example/qemu-mips-static squashfs-root
```

```
# From squashfs-root
chroot ./ ./qemu-mips-static bin/ls
```
