# DEF CON CTF Qualifier 2022

## same old

Tags: _hash-collision_ _hash_


## Summary

Bruteforce a crc32 collision with the word "the" and any number of chars prefixed by your team name.

> There are probably smarter ways to do this and most likely existing tools, but it was faster to just write this and run 8 in parallel.

## Solve

```c
// gcc -Wall -O3 -s -o solve solve.c -lz

#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define TEAM "burner_herz0g"
#define LENGTH 6

int main()
{
    char *s = "the";
    char *l = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int llen = strlen(l);
    int len = strlen(TEAM);
    int tlen = len + LENGTH;
    unsigned char test[tlen + 1];
    unsigned long seed, source, target = crc32(0, (unsigned char *)s, strlen(s));
    struct timeval time;

    gettimeofday(&time,NULL);
    seed = (time.tv_sec * 1000) + (time.tv_usec / 1000);
    srand(seed);
    printf("%lx\n",target);
    strcpy((char *)test,TEAM);
    printf("%s\n",test);
    test[tlen] = 0;

    do {
        for(int i = len; i < tlen; i++) test[i] = l[rand() % llen];
        source = crc32(0, test, tlen);
    } while(source != target);

    printf("%s %lx %ld\n",test,source,seed);
    return 0;
}
```

`LENGTH` should be at least `6` to have enough bits (>=32) for a crc32 collision.  The description (unable to capture post CTF) states the appended chars to be limited to alphanumeric.  That's 62 chars that can be represented by 6 bits (not 8) each, so you'll need at least 6.

Just build and run a handful in parallel and you'll get a solution in about a minute, e.g.:

```bash
# time ./solve
3c456de6
burner_herz0g
burner_herz0g59hZ53 3c456de6 1653715620215
./solve  18.68s user 0.00s system 100% cpu 18.662 total
```
