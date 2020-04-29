## Linux 

## Windows 

## Android 

### Quick Reference

- Take screenshots from ADB: `adb shell screencap -p | perl -pe 's/\x0D\x0A/\x0A/g' > screen.png`

### Tools 

- A framework for automated extraction of static and dynamic features from Android applications: <https://github.com/alexMyG/AndroPyTool>

### Issues 

- `seccomp` `ptrace`
  - Issue 1718: Android: ptrace hole makes seccomp filter useless on devices with kernel <4.8:
  <https://bugs.chromium.org/p/project-zero/issues/detail?id=1718>
- Chainspotting: Building Exploit Chains with Logic Bugs: <https://labs.mwrinfosecurity.com/publications/chainspotting-building-exploit-chains-with-logic-bugs/>

### Techniques 

**Dynamic Analysis**

```bash
# unpack and decompile whole APK to be patched later
apktool d application.apk -o re_project0/

# create folder for all decompiled smali sources
mkdir -p re_project0/src

# copy all the smali code to sources folder
cp -R re_project0/smali*/* re_project0/src
```

```xml
<application android:debuggable="true" android:allowBackup="true" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:largeHeap="true" android:name="org.horaapps.leafpic.App" android:theme="@style/Theme.AppCompat">
```

```bash
apktool b re_project0/
```

```bash
keytool -genkey -v -keystore key.keystore -alias sign -keyalg RSA -keysize 2048 -validity 10000
```

### References

- <https://malacupa.com/2018/11/11/debug-decompiled-smali-code-in-android-studio-3.2.html>

## iOS

### Codes

- `*5005*78283#`
  - Dial to dump baseband to /Library/Logs/Baseband
  - Use idevicecrashreport to copy to pc
  - <https://twitter.com/userlandkernel/status/1081627817975128069>
- `*#5005*5667#`
  - Crash commcenter / baseband
  - <https://twitter.com/userlandkernel/status/1081630998431977473>

### References

- iOS Pentesting Tools Part 3: Frida and Objection: <https://www.allysonomalley.com/2018/12/20/ios-pentesting-tools-part-3-frida-and-objection/>

## MacOS

### Important files 

```
/etc/fstab
/etc/master.passwd
/etc/resolv.conf
/etc/sudoers
/etc/sysctl.conf
```

### Defense

**Tools**

- xnumon - monitor macOS for malicious activity: <https://github.com/droe/xnumon>

## Solaris

- <https://blogs.oracle.com/solaris/understading-rbac-v2>
