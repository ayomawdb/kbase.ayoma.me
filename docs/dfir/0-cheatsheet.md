# Cheatsheet

## Look for deleted files

### Linux

Locations:
```
lost+found
```

Commands:
```
strings /dev/sdb
```
```
sudo dcfldd if=/dev/sdb of=/home/pi/usb.dd
testdisk /home/pi/usb.dd
```
