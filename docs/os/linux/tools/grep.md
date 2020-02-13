| Option     | Details     |
| :--------- | :---------- |
| `-i`       | Ignore case |
| `-r` `-R`  | Recursive  `grep -R "example" /etc/apache2/` |
| `-w`       | Match words |
| `-e`       | Regex match `grep -w -e 'word1|word2' /path/to/file`|
| `-n`       | Line number |
| `-c`       | Count |
| `-v`       | Invert  |
| `-x`       | Exact match  |
| `-l`   | File names with match  |
| `-L`   | File names without match  |

- Color word root: `grep --color root /etc/passwd`
- OR: `grep -e how -e to -e forge *.txt`

## References
- https://www.howtoforge.com/tutorial/linux-grep-command/
