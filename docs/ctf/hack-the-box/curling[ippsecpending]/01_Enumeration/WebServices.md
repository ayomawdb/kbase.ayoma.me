## Nikto

## DirBuster / GoBuster

## SSL Cert

## WebDav

## CMS
```
_)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
 .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  (
 \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
           (1337.today)

   --=[OWASP JoomScan
   +---++---==[Version : 0.0.7
   +---++---==[Update Date : [2018/09/23]
   +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
   --=[Code name : Self Challenge
   @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://10.10.10.150 ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.8.8

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing :
http://10.10.10.150/administrator/components
http://10.10.10.150/administrator/modules
http://10.10.10.150/administrator/templates
http://10.10.10.150/images/banners


[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://10.10.10.150/administrator/

[+] Checking robots.txt existing
[++] robots.txt is not found

[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found


Your Report : reports/10.10.10.150/

```

```
droopescan  scan joomla -u http://10.10.10.150
[+] Possible interesting urls found:                                            
    Detailed version information. - http://10.10.10.150/administrator/manifests/files/joomla.xml
    Login page. - http://10.10.10.150/administrator/
    License file. - http://10.10.10.150/LICENSE.txt
    Version attribute contains approx version - http://10.10.10.150/plugins/system/cache/cache.xml

[+] Possible version(s):
    3.8.10
    3.8.11
    3.8.11-rc
    3.8.12
    3.8.12-rc
    3.8.13
    3.8.7
    3.8.7-rc
    3.8.8
    3.8.8-rc
    3.8.9
    3.8.9-rc

[+] Scan finished (0:00:06.019226 elapsed)
```

## Wordlist
```
cewl http://10.10.10.150/
CeWL 5.4.3 (Arkanoid) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
the
curling
Curling
site
you
and
are
Print
for
Home
Cewl
Uncategorised
The
your
first
post
Begin
Content
User
best
End
Right
Sidebar
Username
Password
Forgot
Details
Written
Super
Category
Published
May
Hits
down
know
its
true
What
object
article
planet
get
sheet
can
feet
droplets
water
ice
from
more
games
Watching
time
There
this
amazing
username
password
Body
Header
You
here
Main
Menu
Login
Form
Remember
Log
Footer
Back
Top
secret
txt
with
end
Good
question
First
let
bit
jargon
playing
surface
called
Sheet
dimensions
vary
but
they
usually
around
long
about
wide
covered
tiny
that
become
cause
stones
curl
deviate
straight
path
These
known
pebble
absolutely
sport
watch
television
particularly
viewers
looking
escape
frantic
faster
bigger
higher
grind
most
televised
basketball
hockey
hyped
feel
like
drinking
Red
Bull
doing
jumping
jacks
makes
want
drink
glass
red
wine
lie
shag
carpet
deliberate
Thoughtful
even
move
very
slowly
players
spend
lot
talking
strategy
nods
quiet
words
encouragement
rarely
there
disagreements
When
comes
team
member
play
their
turn
sliding
stone
moves
elegant
wind
push
off
slide
gentle
release
Such
poise
finesse
Hey
website
Stay
tuned
content
win
Floris
Email
Address
RSS
Atom
email
address
account
will
Next
item
span
Prev
Please
enter
Submit
verification
code
items
leading
row
associated
Your
emailed
file
sent
Once
have
received
able
choose
new
```

## HTML Comments
```
secret.txt
```
Base64 Decode to get `Curling2018!`
