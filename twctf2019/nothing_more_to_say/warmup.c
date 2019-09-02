// gcc -fno-stack-protector -no-pie -z execstack  warmup.c -o warmup
#include <stdio.h>

void init_proc() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}


int main(void) {
    char buf[0x100];
    init_proc();
    puts("Hello CTF Players!\nThis is a warmup challenge for pwnable.\nWe provide some hints for beginners spawning a shell to get the flag.\n\n1. This binary has no SSP (Stack Smash Protection). So you can get control of instruction pointer with stack overflow.\n2. NX-bit is disabled. You can run your shellcode easily.\n3. PIE (Position Independent Executable) is also disabled. Some memory addresses are fixed by default.\n\nIf you get stuck, we recommend you to search about ROP and x64-shellcode.\nPlease pwn me :)");
    gets(buf);
    printf(buf);
    return 0;
}
