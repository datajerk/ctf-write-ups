# csictf 2020

## The Scraps

I rarely do write-ups for smaller solves, but then all that history gets lost and is hard to find later when I need it, so, here's a rundown of some of the easy ones, you know, for the points.

> All I could find, post CTF on my <strike>HD</strike> SSD.


### Machine Fix

```
We ran a code on a machine a few years ago. It is still running however we forgot
what it was meant for. It completed n=523693181734689806809285195318 iterations
of the loop and broke down. We want the answer but cannot wait a few more years. 
Find the answer after n iterations to get the flag.

The flag would be of the format csictf{answer_you_get_from_above}.
```

`code.py`:

```python
def convert (n):
    if n == 0:
        return '0'
    nums = []
    while n:
        n, r = divmod(n, 3)
        nums.append(str(r))
    return ''.join(reversed(nums))

count=0
n=1
while(n<=523693181734689806809285195318):
	str1=convert(n)
	str2=convert(n-1)
	str2='0'*(len(str1)-len(str2))+str2
	for i in range(len(str1)):
		if(str1[i]!=str2[i]):
			count+=1
	n+=1

print(count)
```

Solution 1:

After testing `n` with powers of 10 it's clear it converges to `n * 1.5`.  Starting from `785539772602034710213927792977` (`523693181734689806809285195318 * 3 // 2`) and counting down, submit flags until a match (`785539772602034710213927792950`), 27 submissions.

Solution 2:

Looking at the increments to count:

`1 1 2 1 1 2 1 1 3 1 1 2 1 1 2 1 1 3 1 1 2 1 1 2 1 1 4 ...`

The following will add that up:

```
#!/usr/bin/python3

import sys

n = int(sys.argv[1],10)
c = 0; m = 0; d = 1
while True:
    t = n // (3 ** m) - n // (3 ** (m+1))
    c += d * t; m += 1; d += 1
    if t == 0:
        break
print(c)
```

`785539772602034710213927792950`

### Blasie

```
I recovered a binary from my teacher's computer. I tried to reverse it but I couldn't.
```

Open up the binary in Ghidra and reproduce `f` and `C` in python:

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

Output:

```
[+] Opening connection to chall.csivit.com on port 30808: Done

csictf{y0u_d1sc0v3r3d_th3_p4sc4l's_tr14ngl3}
```