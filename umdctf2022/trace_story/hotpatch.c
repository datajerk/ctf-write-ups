#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>

int main(int argc, char *argv[])
{
	pid_t pid;
	struct user_regs_struct regs;
	unsigned long ins;
	unsigned long addr = 0x401802;
	unsigned long addr_exit = 0x401827;
	unsigned long txt = 0x402011;

	if (argc != 2) {
		printf("usage: %s [pid]\n", argv[0]);
		return 1;
	}

	pid = atoi(argv[1]);
	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	//wait(NULL);
	sleep(1);

	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	printf("rip: %llx\n",regs.rip);

	//puts after read patch
	ptrace(PTRACE_POKETEXT, pid, addr,    0x9090909090909090);
	ptrace(PTRACE_POKETEXT, pid, addr+8,  0x9090909090909090);
	ptrace(PTRACE_POKETEXT, pid, addr+16, 0x9090909090909090);
	ptrace(PTRACE_POKETEXT, pid, addr+24, 0xf789489090909090);

	//patchout exit
	ptrace(PTRACE_POKETEXT, pid, addr_exit+0, 0x9090909090909090);
	ptrace(PTRACE_POKETEXT, pid, addr_exit+2, 0x9090909090909090);

	//readstory.txt is now flag
	ptrace(PTRACE_POKETEXT, pid, txt, 0x67616c66);

	ptrace(PTRACE_DETACH, pid, NULL, NULL);

	return 0;
}
