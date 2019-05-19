# Tools

- [Crypto Operations](http://rumkin.com/tools/cipher/)
- [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
```
RsaCtfTool.py --publickey public-key.pub --uncipher cipher-text.crypt
```
- [PadBuster - Padding Oracle Attack](https://github.com/GDSSecurity/PadBuster)
  - https://blog.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html
```
Decrypt

padbuster http://10.10.10.18
2zKLNWhe0Xt7G4ymYDK%2BEdptckP8a8vO 8
-cookies auth=2zKLNWhe0Xt7G4ymYDK%2BEdptckP8a8vO
-encoding 0

Encrypt

padbuster http://10.10.10.18
2zKLNWhe0Xt7G4ymYDK%2BEdptckP8a8vO 8
-cookies auth=2zKLNWhe0Xt7G4ymYDK%2BEdptckP8a8vO
-encoding 0 -plaintext user=admin
```
- [Elliptic Curve Cryptography for Python - https://pypi.org/project/seccure/](https://pypi.org/project/seccure/)

## Encoding/Decoding

- IP to Decimal: [https://www.browserling.com/tools/ip-to-dec](https://www.browserling.com/tools/ip-to-dec)

Binary to ASCII
```
echo"010000" | perl -lpe '$_=pack"B*",$_'
```

- Ook and Brainfuck
  - [https://www.splitbrain.org/_static/ook/](https://www.splitbrain.org/_static/ook/)
  - [https://www.splitbrain.org/services/ook](https://www.splitbrain.org/services/ook)
  - [https://github.com/splitbrain/ook](https://github.com/splitbrain/ook)

### Base64

Decode
```
base64 -d <<< NmQy
echo "NmQy" | base64 -d
```

Encode
```
base64 <<< NmQy
echo "NmQy" | base64
```

## Hashes

- [https://hashkiller.co.uk](https://hashkiller.co.uk)

## Concurrency

- Multi-threaded CPU miner: [https://github.com/hyc/cpuminer-multi](https://github.com/hyc/cpuminer-multi)
