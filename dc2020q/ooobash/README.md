# DEF CON CTF Qualifier 2020

## ooobash

> Execute 'getflag' to get the flag.
>
> [ooobash](ooobash) [live here](https://archive.ooo/c/ooobash/350/)

Tags: _rev_ _x86-64_

Exploit:

```python
#!/usr/bin/python3

from pwn import *

p = remote('ooobash.challenges.ooo', 5000)
p.recvuntil('$ ')
p.sendline('OOOENV=alsulkxjcn92 /bin/bash -L -i 2>/dev/null') # 3,4
p.sendline('if :\nthen\n\n\n\nfalse\nfi') # 12
p.sendline('function fnx { echo  ; } ; fn 1') #  11
p.sendline('declare -r ARO=ARO; declare -r ARO=ARO') # 10
p.sendline('echo 1 > /dev/tcp/127.0.0.1/53') # 7
p.sendline('f() { return 57; }; f') # 6
p.sendline('set -o sneaky; echo 1 > /tmp/.sneakyhihihiasd') # 2
p.sendline('set -o noclobber; echo 1 2> /tmp/badr3d1rzzzzzza') # 1
p.sendline('unlockbabylock') # 0
p.sendline('kill -10 $$') # 8
p.sendline('cat <<EOF >/dev/null\na\nb\nc\nEOF') # 5
p.sendline("alias yo='echo yo!'") # 9
p.sendline("alias yo='echo yo!'") # 9
p.sendline('getflag')
p.stream()
```

Output:

```bash
# ./sol.py
[+] Opening connection to ooobash.challenges.ooo on port 5000: Done
OOOENV=alsulkxjcn92 /bin/bash -L -i 2>/dev/null
unlocking leetness (3)
unlocking vneooo (4)
unlocking ifonly (12)
unlocking fnx (11)
unlocking aro (10)
unlocking n3t (7)
unlocking ret (6)
unlocking verysneaky (2)
unlocking badr3d1r (1)
unlocking unlockbabylock (0)
unlocking sig (8)
unlocking eval (5)
unlocking yo (9)
You are now a certified bash reverser! The flag is OOO{r3VEr51nG_b4sH_5Cr1P7s_I5_lAm3_bU7_R3vErs1Ng_b4SH_is_31337}
```
