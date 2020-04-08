# Cheatsheets

- Nmap: https://blogs.sans.org/pen-testing/files/2013/10/NmapCheatSheetv1.1.pdf
- Wireshark: [https://packetlife.net/media/library/13/Wireshark_Display_Filters.pdf](https://packetlife.net/media/library/13/Wireshark_Display_Filters.pdf)
- TcpDump: [https://packetlife.net/media/library/12/tcpdump.pdf](https://packetlife.net/media/library/12/tcpdump.pdf)
- Netcat: [https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf](https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf)
- Ncat: [https://medium.com/@pentest_it/ncat-cheatsheet-ddc5f07d8533](https://medium.com/@pentest_it/ncat-cheatsheet-ddc5f07d8533)
- Scapy: [https://blogs.sans.org/pen-testing/files/2016/04/ScapyCheatSheet_v0.2.pdf](https://blogs.sans.org/pen-testing/files/2016/04/ScapyCheatSheet_v0.2.pdf)
- 



## Public IP
- [How to Find Your Public IP Address on Linux Command Line](https://www.putorius.net/find-public-ip-address-linux-command-line.html)
```
curl https://ipaddr.pub
```

## MAC to IPv6

```
    take the mac address: for example 52:74:f2:b1:a8:7f
    throw ff:fe in the middle: 52:74:f2:ff:fe:b1:a8:7f
    reformat to IPv6 notation 5274:f2ff:feb1:a87f
    convert the first octet from hexadecimal to binary: 52 -> 01010010
    invert the bit at index 6 (counting from 0): 01010010 -> 01010000
    convert octet back to hexadecimal: 01010000 -> 50
    replace first octet with newly calculated one: 5074:f2ff:feb1:a87f
    prepend the link-local prefix: fe80::5074:f2ff:feb1:a87f
    done!
```
> <https://ben.akrin.com/?p=1347>

```
format_eui_64() {
    local macaddr="$1"
    printf "%02x%s" $(( 16#${macaddr:0:2} ^ 2#00000010 )) "${macaddr:2}" \
        | sed -E -e 's/([0-9a-zA-Z]{2})*/0x\0|/g' \
        | tr -d ':\n' \
        | xargs -d '|' \
        printf "%02x%02x:%02xff:fe%02x:%02x%02x"
}
```
> <https://stackoverflow.com/questions/27693120/convert-from-mac-to-ipv6>



# HTTP Request with /dev/tcp

```
exec 3<>/dev/tcp/(INTERNAL IP ADDRESS)/80
echo -e "GET / HTTP/1.1\r\nHost: (INTERNAL IP ADDRESS)\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (X11;Linux x86_64...) Gecko/20100101 Firefox/60.0\r\n\r\n" >&3
cat <&3
```

## Flags
- TCP Flag Key: http://rapid.web.unc.edu/resources/tcp-flag-key/