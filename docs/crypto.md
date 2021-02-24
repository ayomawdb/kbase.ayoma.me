## Tools

- Compare unknown cipher against ACA cipher types: <http://web.archive.org/web/20120624074941/http://home.comcast.net/~acabion/refscore.html>
- Crypto Operations: <http://rumkin.com/tools/cipher/>
- RsaCtfTool: <https://github.com/Ganapati/RsaCtfTool>
    ```bash
    RsaCtfTool.py --publickey public-key.pub --uncipher cipher-text.crypt
    ```
- One time pad decipher: <https://www.braingle.com/brainteasers/codes/onetimepad.php#form>
- Ceasar Cipher: https://www.xarg.org/tools/caesar-cipher/
- Ceaser Decode:
    ```bash
    echo "string" | tr '[A-Za-z]' '[N-ZA-Mn-za-m]'
    ```
- Vigenere Cipher: https://www.dcode.fr/vigenere-cipher
- Elliptic Curve Cryptography for Python: <https://pypi.org/project/seccure/>
- SSL Config Generator: <https://ssl-config.mozilla.org/>

### PadBuster

- Padding Oracle Attack
- <https://github.com/GDSSecurity/PadBuster>
- <https://blog.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html> 
- Decrypt:
    ```bash
    padbuster <http://10.10.10.18> 2zKLNWhe0Xt7G4ymYDK%2BEdptckP8a8vO 8 -cookies auth=2zKLNWhe0Xt7G4ymYDK%2BEdptckP8a8vO -encoding 0
    ```
- Encrypt
    ```bash
    padbuster <http://10.10.10.18> 2zKLNWhe0Xt7G4ymYDK%2BEdptckP8a8vO 8 -cookies auth=2zKLNWhe0Xt7G4ymYDK%2BEdptckP8a8vO -encoding 0 -plaintext user=admin
    ```

### OpenSSL 

#### General

- Create key pair: `openssl genrsa -out keypair.pem 2048`
- Extracting public key from rsa context: `openssl rsa -in keypair.pem -pubout -out publickey.crt`
- Convert public key to PKCS#8: `openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key`
- Retrieve exponent and modulus values: `openssl rsa -pubin -in publickey.crt -text -noout`
- Extracting Public Key - Using private key: `openssl pkey -in example.key -pubout`
- Extracting Public Key - From certificate: `openssl x509 -in example.crt -pubkey -noout`

#### CSR and Signing 

Create CSR and private key
```bash
openssl req -new -newkey rsa:2048 -nodes -keyout example.key -out example.csr

#OR 

openssl genrsa -out example.key 2048
openssl req -new -key example.key -out example.csr 
```

Check CSR
```bash
openssl req -verify -in example.csr -text -noout
```

Sign CSR enforcing SHA256
```bash
openssl x509 -req -days 360 -in example.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out example.crt -sha256
```

Self-sign
```bash
openssl x509 -req -days 365 -in example.csr -signkey example.key -out example.crt
```

CA-sign
```bash
openssl x509 -req -in example.csr -CA ca.crt -CAkey ca.key -set_serial 9999 -extensions client -days 9999 -outform PEM -out example.crt
```

Create P12
```bash
openssl pkcs12 -export -clcerts -in server.crt -inkey server.key -out cert.p12
```

## Modes 

- ECB
  - ECB cipher being employed operates on 8-byte blocks of data, and the blocks of plaintext map to the corresponding blocks of ciphertext 
  - manipulate the sequence of ciphertext blocks so as to modify the corresponding plaintext
  - Ex: change UID value of a token
- CBC
  - each block of plaintext is encrypted it is XORed against the preceding block of ciphertext
  - manipulating a single individual block of the token, the attacker can systemati- cally modify the decrypted contents of the block that follows it
  - Use bit-flipping (burp) to guess values

## Encoding/Decoding

- IP to Decimal: <https://www.browserling.com/tools/ip-to-dec>
- Binary to ASCII:
    ```bash
    echo "010000" | perl -lpe '$_=pack"B*",$_'
    ```
- Ook and Brainfuck
  - <https://www.splitbrain.org/_static/ook/>
  - <https://www.splitbrain.org/services/ook>
  - <https://github.com/splitbrain/ook>

- Base64 Decode:
    ```bash
    base64 -d <<< NmQy 
    echo "NmQy" | base64 -d
    ```
- Base64 Encode:
    ```bash
    base64 <<< NmQy
    echo "NmQy" | base64
    ```

## Hashes

- <https://hashkiller.co.uk>

## Concurrency

- Multi-threaded CPU miner: <https://github.com/hyc/cpuminer-multi>

## References 

- [How to create a self-signed SSL Certificate](https://www.akadia.com/services/ssh_test_certificate.html)
- [How to Set Up Mutual TLS Authentication to Protect Your Admin Console](https://blog.codeship.com/how-to-set-up-mutual-tls-authentication/)
- MD5 collisions of any pair of PDFs: https://twitter.com/angealbertini/status/1075417521799528448
- raccoon: <https://raccoon-attack.com/>
  - all leading zero bytes in the premaster secret are stripped before used in further computations
  - Since the resulting premaster secret is used as an input into the key derivation function, which is based on hash functions with different timing profiles, precise timing measurements may enable an attacker to construct an oracle from a TLS server
