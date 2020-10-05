#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

char shellcode[16];

int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    long * n = alloca(8);
    char * guess = alloca(64);
    *n = (long) &main;

    printf("Work for the respectable software company, Neo.\n");
    read(0, guess, 128);

    if(*n >> 32 == atoi(guess)) {
        system("/bin/sh");
    }
}
