# TJCTF 2020

## ASMR

> 60
>
> I heard [ASMR](asmr.asm) is a big hit on the internet!
>
> Written by KyleForkBomb

Tags: _rev_ _x86-64_ _xor_


## Summary

Assembly the code, start up the service, put in the correct password, get an audio file, listen to the flag.

> I was just informed via Discord that this challenge was changed part way through the CTF.  This is a write up of the original challenge, including the original source.


## Analysis

### Build, Test, Play

Build:

```
nasm -o asmr.o -f elf64 asmr.asm
ld -o asmr asmr.o
```

Test:

```
# ./asmr
```

Nothing.  Test again:

```
# strace ./asmr
execve("./asmr", ["./asmr"], 0x7ffcc3587830 /* 14 vars */) = 0
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
setsockopt(3, SOL_SOCKET, SO_REUSEADDR, "\1\0\0\0\0\0\0\0", 8) = 0
bind(3, {sa_family=AF_INET, sin_port=htons(1337), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
listen(3, 1)                            = 0
accept(3, NULL, NULL
```

Ah, a network service, so:

```
# nc localhost 1337
Enter password:
```

There are two checks: _is the input `0x11` (17) characters_ (16 characters for the password + `\n`), and, _is the password `yellow_sunflower`_:

```
        cmp     rax, 0x11               <--- length
        jne     label5
        lea     rax, [rbp-0x50]
        cmp     BYTE [rax+16], 0x0a
        jne     label5
        mov     BYTE [rax+16], 0x00
        jmp     label2
label1:
        xor     BYTE [rax], 0x69        <--- xor 0x69 with (yellow_sunflower)
        inc     rax                                     |
label2:                                                 |
        cmp     BYTE [rax], 0x00                        |
        jne     label1                                  |
        mov     rax, 0x1a361e0605050c10 <---------------+
        cmp     QWORD [rbp-0x50], rax                   |
        jne     label5                                  |
        mov     rax, 0x1b0c1e06050f071c <---------------+
```

From python:

```
>>> bytes.fromhex(hex(int('0x' + '69' * 16,16) ^ 0x1b0c1e06050f071c1a361e0605050c10)[2:])[::-1]
b'yellow_sunflower'
```

> To find the above quickly I just used GDB and followed the code execution.  Once I saw the `xor 0x69`, I just xor'd the entire binary and used `strings` to get the password.

After entering the correct password, a binary stream is emitted:

```
Ogg data, Vorbis audio, mono, 8000 Hz, ~28000 bps, created by: Xiph.Org libVorbis I
```

[Listen](foo) and get the flag.


## Solve

```shell
# ./asmr & sleep 1; echo "yellow_sunflower" | nc localhost 1337 | dd bs=16 skip=1 >foo
# play foo
```

> This dude is seriously creepy.

Flag:

```
tjctf{bub6le_wr4p_p0p}
```
