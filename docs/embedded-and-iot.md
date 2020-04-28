## Lab Setup

- RPi as poor man's hardware hacking tool: <https://payatu.com/using-rasberrypi-as-poor-mans-hardware-hacking-tool/>
- <https://systemoverlord.com/static/attachments/iot_toolkit.pdf>
- OSH Stencils: <https://www.oshstencils.com>

## Quick Reference

- Cross Compiling - Compile for MIPS:
    ```
    mips-linux-gnu-gcc bindshell.c -o bindshell -static
    mips-linux-gnu-strip bindshell
    ```
- ESP
  - Read Flash: `esptool.py -p /dev/ttyUSB0 -b 460800 read_flash 0 0x200000 flash.bin`
  - Check Device config: `espefuse.py --port /dev/ttyUSB0 summary`
- Binwalk
  - Display information: `binwalk -t -vvv example-firmware`
  - Extract: `binwalk -e -t -vvv example-firmware`
  - Entropy Analysis (identity compression / encryption): `binwalk -E example-firmware`
    - <http://www.devttys0.com/2013/06/differentiate-encryption-from-compression-using-math/>
- Repacking Firmware
  - <https://github.com/rampageX/firmware-mod-kit/wiki>
    ```
    ./extract-firmware.sh example-firmware.bin
    ./build-formware.sh
    ```
- Busybox
  - Command Injection: <https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2010/february/busybox-command-injection/>
  - Bind a telnet shell to port 9999: `/bin/busybox telnetd -l/bin/sh -p9999`
- QMUE
  - Run binaries inside a firmware
    ```
    whereis qemu-mips-static
    cp /etc/example/qemu-mips-static squashfs-root
    ```
    ```
    # From squashfs-root
    chroot ./ ./qemu-mips-static bin/ls
    ```
## Test Scenarios

- Replaying of sensor communication
- Pair device with controlling application without authorization
   - Using guessable identifiers for linking
- WiFi and other credentials stored in flash

## Techniques 

- Glitching
  - Voltage glitching attacks: <https://twitter.com/d_olex/status/1084700474043813895>
- Side Channel
  - Intel TLBleed: <https://www.theregister.co.uk/2018/06/22/intel_tlbleed_key_data_leak/>

## Collections 

- Searchable FCC ID Database: <https://fccid.io/>
- Command to download all FCC ID documents: <https://rehmann.co/blog/command-download-fcc-id-documents/>
    ```
    for i in $(seq 3 4200000); do curl –referer ‘https://apps.fcc.gov/oetcf/eas/reports/ViewExhibitReport.cfm’ ‘https://apps.fcc.gov/eas/GetApplicationAttachment.html?calledFromFrame=Y&id=’$i -o $i; done
    ```

## Protocols 

### UART / Serial

- All clock speeds are set independently of the signal
   - `baud rate` is the rate at which bits will be transmitted (bits per second).
- There is one `start` bit.
- There is one `stop` bit (a low voltage cycle).
- 8 data bits in the middle.
- 1 parity bit at the end of the data.

**Settings**

Number of data bits/number of parity bits/number of stop bits
8/N/1 (8N1) means 8 data bits, No parity bit, and 1 stop bit

**Common Baud Rates**

- 9600
- 19200
- 38400
- 57600
- 115200

> Ref: Pentesting Hardware - A Practical Handbook by Mark C. <https://github.com/unprovable/PentestHardware>

- UART to Root [Pending]: <https://exfil.co/2019/02/14/uart-to-root-the-harder-way/>

### SPI

- `MISO - Master In Slave Out` - Data flow from the slave units to the master unit
- `MOSI - Master Out Slave In` - Data flow from the
master unit to the slave units
- `SCLK - The clock signal pin` - Rising edge of the clock triggers the level of MISO/MOSI to be read as the current bit by the target device.
- `SS/CS - Slave/Chip Select` - Select a device, this pin is grounded, telling the particular device to listen up.
- `VCC/GND`

**Typical**

![SPI](https://upload.wikimedia.org/wikipedia/commons/thumb/f/fc/SPI_three_slaves.svg/545px-SPI_three_slaves.svg.png)

> <https://en.wikipedia.org/wiki/Chip_select>

**Daisy Chained**

- The SPI port of each slave is designed to send out during the second group of clock pulses an exact copy of the data it received during the first group of clock pulses.
- The whole chain acts as a communication shift register.
- Daisy chaining is often done with shift registers to provide a bank of inputs or outputs through SPI.
- Each slave copies input to output in the next clock cycle until active low SS line goes high.

![SPI](https://upload.wikimedia.org/wikipedia/commons/thumb/9/97/SPI_three_slaves_daisy_chained.svg/545px-SPI_three_slaves_daisy_chained.svg.png)

- SPI mode - is the combination of CPOL and CPHA
- CPOL - Polarity of the clock
   - CPOL=0 is a clock which idles at 0
      - Leading edge is a rising edge
      - Trailing edge is a falling edge
   - CPOL=1 is a clock which idles at 1
      - Leading edge is a falling edge
      - Trailing edge is a rising edge
- CPHA - Timing of the data bits relative to the clock pulses
   - CPHA=0
      - "out" side changes the data on the trailing edge of the preceding clock cycle, while the "in" side captures the data on (or shortly after) the leading edge of the clock cycle
      - First bit must be on the MOSI line before the leading clock edge
   - CPHA=1
      - "out" side changes the data on the leading edge of the current clock cycle, while the "in" side captures the data on (or shortly after) the trailing edge of the clock cycle
      - For the last cycle, the slave holds the MISO line valid until slave select is deasserted.

![CPOL / CPHA](https://upload.wikimedia.org/wikipedia/commons/thumb/6/6b/SPI_timing_diagram2.svg/645px-SPI_timing_diagram2.svg.png)

> <https://en.wikipedia.org/wiki/Serial_Peripheral_Interface>

### I2C

### JTAG

- `TDI - Test Data In`
- `TDO - Test Data Out` - When you daisychain IC’s with JTAG, the TDO of one goes to the TDI of the next, until it loops back to the debug header.
- `TCK - Test Clock` - JTAG clock signal, the rising edge triggering a read operation. TCK is not chained, but rather forms a ’test clock bus’ along with TMS each IC can see the clock and TMS signals.
- `TMS - Test Mode Select` - Read as the clock signal rises, and determines the next state of the internal JTAG controller
- `TRST - Test Reset` - An optional pin that can reset the internal test controller, but this isn’t required.


- Test Access Port (TAP) Controller to handle JTAG commands
- Minimally 3 registers (instruction register, 2 or more data registers)
- State-machine that uses the TMS level to decide what to do after each clock cycle
- TAP controller connects to the boundary cells
- Boundary Cells can raise/lower a leg’s voltage to influence the behavior of the chip

> Ref: Pentesting Hardware - A Practical Handbook by Mark C. <https://github.com/unprovable/PentestHardware>

### SWD

## Tools 

- Glasgow = Bus Pirate + Bus Blaster + Logic Sniffer
  - <https://github.com/whitequark/Glasgow>
  - <https://twitter.com/whitequark/status/985040607864176640>
  - <https://twitter.com/marcan42/status/1090564121068593153>
  - Cutdown version of starshipraider: <https://github.com/azonenberg/starshipraider>
- OpenWRT
  - USB Storage:
    - <https://openwrt.org/docs/guide-user/storage/usb-drives>
    - <https://openwrt.org/docs/guide-user/additional-software/extroot_configuration>
    - <https://wiki.openwrt.org/doc/howto/usb.storage>
    - <https://wiki.openwrt.org/doc/howto/extroot>
- FACT - The Firmware Analysis and Comparison Tool: <https://fkie-cad.github.io/FACT_core/>
- Platform Firmware Auditing Tool: <https://github.com/PreOS-Security/fwaudit>
- BIOS - <https://github.com/chipsec/chipsec>

## Specific 

### ATMs

**References:**

- ATM LOGIC ATTACKS: SCENARIOS: <https://www.ptsecurity.com/upload/corporate/ww-en/analytics/ATM-Vulnerabilities-2018-eng.pdf>

### Automobile 

**Tools:**

- canalyzat0r: <https://amp.kitploit.com/2019/02/canalyzat0r-security-analysis-toolkit.html?amp=1&m=1>

**References:**

- Automobile Hacking, Part 1: The CAN Protocol: <https://www.hackers-arise.com/single-post/2017/08/04/Automobile-Hacking-Part-1-The-CAN-Protocol>
- Automobile Hacking, Part 2: The can-utils or SocketCAN: <https://www.hackers-arise.com/single-post/2017/08/08/Automobile-Hacking-Part-2-The-can-utils-or-SocketCAN>
- Automobile Hacking, Part 3: Metasploit for Car Hacking: <https://www.hackers-arise.com/single-post/2017/10/19/Automobile-Hacking-Part-3-Metasploit-for-Car-Hacking>
- Automobile Hacking, Part 4: How to Hack the Keyless Entry System: <https://www.hackers-arise.com/single-post/2018/12/05/Automobile-Hacking-Part-4-How-to-Hack-the-Keyless-Entry-System>
- Awesome Vehicle Security: <https://github.com/jaredthecoder/awesome-vehicle-security>
- <https://twitter.com/0xcharlie/status/1014892446495305733>

### Bluetooth 

**References:**

- A Bluetooth low energy capture the flag: <https://github.com/hackgnar/ble_ctf>
- My notes on Hacking BLE – list of resources: <https://www.davidsopas.com/my-notes-on-hacking-ble-list-of-resources/>

### Cameras 

**Tools:**

- Pentax Hacker Development Kit: <https://github.com/i-am-shodan/PHDK>
  - <https://www.dropbox.com/s/ogez7sb4b0cw92g/hacking_pentax_k30.pdf>
- Canon Hack Development Kit: <http://chdk.wikia.com/wiki/CHDK>

### Locks 

**References: **

- How to open a Tapplock over BLE in under two seconds: https://www.pentestpartners.com/security-blog/totally-pwning-the-tapplock-smart-lock/

### Printers 

**Discovery:**

- Windows
  - SharpPrinter - Discover Printers: <https://github.com/rvrsh3ll/SharpPrinter>
  - ListNetworks - Enumerate all visible network printers in local network: <https://github.com/vinifr/-ListNetworks>
- Linux
  - Praeda - Automated printer data harvesting tool: <http://h.foofus.net/?page_id=218>

**Exploitation:**

- PRET - Printer Exploitation Toolkit: <https://github.com/RUB-NDS/PRET>
- praedasploit - <https://github.com/MooseDojo/praedasploit>

**Attack Patterns:**

- Plunder Pillage & Print: <https://hackinparis.com/data/slides/2014/DeralHeilandandPeterArzamendi.pdf>
- LDAP/SMB/SMTP Pass-Back-Attack: <http://foofus.net/goons/percx/praeda/pass-back-attack.pdf>
  - LDAP - power address book functionality
  - SMB - saving scans to file shares
  - SMTP - scan to email
- Export configuration and look for credentials
- LDAP traffic is unencrypted (usually), can MITM

**Guides:**

- An Introduction to Printer Exploitation: <https://0x00sec.org/t/an-introduction-to-printer-exploitation/3565>

### Ships 

**Shodan Searches:**

- org:"Inmarsat Solutions US"
  - Login for Globe wireless
- title:"sailor 900"
  - Sat antenna details
  - Exploit: https://www.exploit-db.com/exploits/35932
  - Default credentials: admin/1234
- html:commbox
  - KVH CommBox terminals
  - Vessel name / network structure leaked
  - "Show Users" link (or can request the content by appending /rest.php?action=QCgetActiveUsers)

**Tools: **

- Vuln Ship Tracker: <https://ptp-shiptracker.herokuapp.com/>

**Terms:**

- `ECDIS` are the electronic chart systems that are needed to navigate.
- `AIS transceiver` - system that ships use to avoid colliding with each other.
- `NMEA 0183` messages
  - Ethernet and serial networks are often ‘bridged’ at several points (GPS,satcom terminal, ECDIS)
  - OT systems are used to control the steering gear, engines, ballast pumps and lots more.
  - They communicate using  NMEA 0183 messages.
  - No message authentication, encryption or validation (only 2 byte XOR checksum)

**Attack Patterns:**

- Spoof the `ECDIS` using the vulnerable config interface, 'grow' the ship and 'jump' it in to the shipping lanes.
  - Other ships AIS will alert the ships captain to a collision scenario
- MitM and change NMEA 0183 messages to read differently
  - Ex: change the rudder command by modifying a GPS autopilot command

**References:**

**Summarized References:**

- <https://www.pentestpartners.com/security-blog/osint-from-ship-satcoms/>
- <https://www.pentestpartners.com/security-blog/hacking-tracking-stealing-and-sinking-ships/>

### UEFI

**References:**

- UEFI_EXPLOITATION_MASSES_FINAL: <https://github.com/eclypsium/Publications/blob/master/2018/DEFCON26/DC26_UEFI_EXPLOITATION_MASSES_FINAL.pdf>

**Tools:**

- EDK II Project - A modern, feature-rich, cross-platform firmware development environment for the UEFI and PI specifications from www.uefi.org: <https://github.com/tianocore/edk2>
- RaspberryPiPkg - 64-bit Tiano Core UEFI for the Raspberry Pi 3 (with devices, Linux, NetBSD, FreeBSD and Windows on Arm!): <https://github.com/andreiw/RaspberryPiPkg>
- uefi-firmware-parser - Parse BIOS/Intel ME/UEFI firmware related structures: Volumes, FileSystems, Files, etc: <https://github.com/theopolis/uefi-firmware-parser>

## References

### New References
- Twinkly Twinkly Little Star: <https://labs.mwrinfosecurity.com/blog/twinkly-twinkly-little-star>
- search for Xiaomi scooters lock & unlock the devices: <https://github.com/rani-i/Mi365Locker>
- Mass play any YouTube video, terminate apps and rename Chromecast device(s) obtained from Shodan.io: <https://github.com/649/Crashcast-Exploit>
- Project Alias is an open-source parasite to train custom wake-up names for smart home devices while disturbing their built-in microphone: <https://github.com/bjoernkarmann/project_alias>
- 35C3 - Modchips of the State: <https://www.youtube.com/watch?v=C7H3V7tkxeA> (BNC backdoor designed to be inserted into a _resistor_ sitting between the SPI flash and the BNC chip)
- Rooting the FireTV Cube and Pendant with FireFU: <https://blog.exploitee.rs/2018/rooting-the-firetv-cube-and-pendant-with-firefu/>
- Thunderclap
  - <https://twitter.com/marcan42/status/1100655030711939072>

### Summarized References
- <https://limitedresults.com/2019/01/pwn-the-lifx-mini-white/>
