## SSL Commands 

### Extract Public Key

Create public key from private key

```
openssl pkey -in example.key -pubout
```

Public key from certificate

```
openssl x509 -in example.crt -pubkey -noout
```

### CSR and Signing 

Create CSR and private key

```
openssl req -new -newkey rsa:2048 -nodes -keyout example.key -out example.csr

#OR 

openssl genrsa -out example.key 2048
openssl req -new -key example.key -out example.csr 
```

Check CSR

```
openssl req -verify -in example.csr -text -noout
```

Sign CSR enforcing SHA256

```
openssl x509 -req -days 360 -in example.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out example.crt -sha256
```

Self-sign

```
openssl x509 -req -days 365 -in example.csr -signkey example.key -out example.crt
```

CA-sign

```
openssl x509 -req -in example.csr -CA ca.crt -CAkey ca.key -set_serial 9999 -extensions client -days 9999 -outform PEM -out example.crt
```

Create P12

```
openssl pkcs12 -export -clcerts -in server.crt -inkey server.key -out cert.p12
```

## Rerefences 

- [How to create a self-signed SSL Certificate](https://www.akadia.com/services/ssh_test_certificate.html)
- [How to Set Up Mutual TLS Authentication to Protect Your Admin Console](https://blog.codeship.com/how-to-set-up-mutual-tls-authentication/)