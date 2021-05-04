#!/usr/bin/python3

from pwn import *

p = remote('ooobash.challenges.ooo', 5000)
p.recvuntil('$ ')
p.sendline('OOOENV=alsulkxjcn92 /bin/bash -L -i 2>/dev/null') # 3,4
p.sendline('if :\nthen\n\n\n\nfalse\nfi') # 12
p.sendline('function fnx { echo  ; } ; fn 1') # 11
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
