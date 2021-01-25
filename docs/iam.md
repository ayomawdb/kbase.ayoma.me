# IAM

## Kerberos

Moved to dedicated section at <https://kbase.ayoma.me/iam-kerberos/>

## JWT

- `jku` can be changed to a different URL, so that the validator will pick the key material from attacker controlled endpoint. (Ref: AttackDefense - JWT CTF)

**References**

- Stop using JWT for sessions: http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/
- No Way, JOSE! Javascript Object Signing and Encryption is a Bad Standard That Everyone Should Avoid: https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid

## OAuth2

**Bug Reports**

- Twitter: Insufficient OAuth callback validation which leads to Periscope account takeover: https://hackerone.com/reports/110293
