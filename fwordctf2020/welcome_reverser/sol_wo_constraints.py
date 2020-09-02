#!/usr/bin/python3

import angr, time, io

FIND_ADDR=0x40165d
t=time.time()
binary = open('./welcome','rb').read()
proj = angr.Project(io.BytesIO(binary),auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.DFS())
simgr.explore(find=FIND_ADDR)
print(simgr.found[0].posix.dumps(0))
print(time.time() - t,end=" seconds\n")

from pwn import *

p = remote('welcome.fword.wtf', 5000)
p.recvuntil('Hello give me the secret number so i can get the flag:')
p.sendline(simgr.found[0].posix.dumps(0)[:16])
print(p.recvuntil('FwordCTF{') + p.recvuntil('}'))

