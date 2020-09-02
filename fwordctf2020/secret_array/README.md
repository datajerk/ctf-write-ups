# FwordCTF 2020

## Secret Array

>  283
>
> `nc secretarray.fword.wtf 1337`
>
> Author: KOOLI

Tags: _misc_


## Summary

```
I have a 1337 long array of secret positive integers. The only information I
can provide is the sum of two elements. You can ask for that sum up to 1337
times by specifing two different indices in the array.

[!] - Your request should be in this format : "i j". In this case, I'll respond
by arr[i]+arr[j]

[!] - Once you figure out my secret array, you should send a request in this
format: "DONE arr[0] arr[1] ... arr[1336]"

[*] - Note 1: If you guessed my array before 1337 requests, you can directly
send your DONE request.
[*] - Note 2: The DONE request doesn't count in the 1337 requests you are
permitted to do.
[*] - Note 3: Once you submit a DONE request, the program will verify your
array, give you the flag if it's a correct guess, then automatically exit.

START:
```

## Solve

```
#!/usr/bin/env python

from pwn import *

p = remote('secretarray.fword.wtf', 1337)
context.log_level = 'INFO'
context.log_file = 'foo.log'
p.recvuntil('START:\n')

n = 1337 * [0]

p.sendline('0 1')
a = int(p.recvline().strip())
p.sendline('0 2')
b = int(p.recvline().strip())
p.sendline('1 2')
c = int(p.recvline().strip())

n[1] = (b - c - a) / -2
n[0] = a - n[1]
n[2] = c - n[1]

log.info('n[0] = ' + str(n[0]))
log.info('n[1] = ' + str(n[1]))
log.info('n[2] = ' + str(n[2]))
log.info('going for it')

ans = 'DONE ' + str(n[0]) + ' ' + str(n[1]) + ' ' + str(n[2])
for i in range(3,1337):
    log.info(str(i))
    p.sendline('0 ' + str(i))
    n[i] = int(p.recvline().strip()) - n[0]
    ans += ' '
    ans += str(n[i])

context.log_level = 'DEBUG'
p.sendline(ans)
print(p.stream())
```

It really wan't necessary to store in an array, just how I started (and think).

Flag:

```
FwordCTF{it_s_all_about_the_math}
```
