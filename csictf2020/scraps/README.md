# csictf 2020

## The Scraps

I rarely do write-ups for smaller solves, but then all that history gets lost and is hard to find later when I need it, so, here's a rundown of some of the easy ones, you know, for the points.

> All I could find, post CTF on my <strike>HD</strike> SSD.


### Machine Fix

```
#!/usr/bin/python3

import sys

n = int(sys.argv[1],10)
c = 0
m = 0
d = 1
while True:
    t = n // (3 ** m) - n // (3 ** (m+1))
    c += d * t
    m += 1
    d += 1
    if t == 0:
        break
print(c)
```


### Blasie


```
#!/usr/bin/python3

from pwn import *
import time

def f(param_1):
    a = 1
    b = 2
    while (b <= param_1):
        a *= b
        b += 1
    return a

def C(param_1,param_2):
    a = f(param_1)
    b = f(param_2)
    c = f(param_1 - param_2)
    return int(a / (b * c))

#binary = ELF('./blaise')
#p = process(binary.path)
p = remote('chall.csivit.com', 30808)

n = int(p.recvline(),10)
for i in range(n+1):
    p.sendline(str(C(n,i)))

flag = p.recvuntil('}').strip().decode()
print('\n' + flag)
```
