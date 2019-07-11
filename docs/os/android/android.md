# Android

## Take screenshots from ADB:
```
adb shell screencap -p | perl -pe 's/\x0D\x0A/\x0A/g' > screen.png
```

## `seccomp` `ptrace`
- Issue 1718: Android: ptrace hole makes seccomp filter useless on devices with kernel <4.8:
https://bugs.chromium.org/p/project-zero/issues/detail?id=1718
- Chainspotting: Building Exploit Chains with Logic Bugs: https://labs.mwrinfosecurity.com/publications/chainspotting-building-exploit-chains-with-logic-bugs/

## Dynamic Analysis

```
# unpack and decompile whole APK to be patched later
apktool d application.apk -o re_project0/

# create folder for all decompiled smali sources
mkdir -p re_project0/src

# copy all the smali code to sources folder
cp -R re_project0/smali*/* re_project0/src
```

```
<application android:debuggable="true" android:allowBackup="true" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:largeHeap="true" android:name="org.horaapps.leafpic.App" android:theme="@style/Theme.AppCompat">
```

```
apktool b re_project0/
```

```
keytool -genkey -v -keystore key.keystore -alias sign -keyalg RSA -keysize 2048 -validity 10000
```



## Tools

- A framework for automated extraction of static and dynamic features from Android applications: [https://github.com/alexMyG/AndroPyTool](https://github.com/alexMyG/AndroPyTool)

## References

- https://malacupa.com/2018/11/11/debug-decompiled-smali-code-in-android-studio-3.2.html