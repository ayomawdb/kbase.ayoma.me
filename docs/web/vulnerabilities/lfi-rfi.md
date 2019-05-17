# LFI / RFI

## LFI to RCE

### RCE with TXT upload
Expose .txt file and use a vulnerable `include` to include the txt file into code (evil.txt.php).

PHP config can be used to disable URL file access. But still local files can be accessed (allow_url_fopen / allow_url_include)

### RCE with Logs
- Use NC to write logs with malicious content to access_logs.
- Connect and just send the attack string (In user-agent etc.).
- Then include the log file (local file inclusion)

### RCE over SQLi
Return <?php echo "test"?> from SQL and see results to check if RCE is possible over SQLi

## References
- Universal LFI for Windows + PHP (using phpinfo): https://rdot.org/forum/showthread.php?t=1134
