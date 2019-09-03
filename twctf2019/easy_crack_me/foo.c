#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "bar.h"

int main(int argc, char **argv)
{
	char cVar1;
	char *flag;
	int iVar2;
	unsigned int uVar3;
	size_t flag_len;
	char *pcVar5;
	long lVar6;
	uint32_t *puVar7;
	unsigned char bVar8;
	int loop_counter1;
	int loop_counter2;
	int local_1b0;
	unsigned int local_1ac;
	int local_1a8;
	int loop_counter3;
	int local_1a0;
	unsigned int local_19c;
	int local_198;
	int local_194;
	int local_190;
	int local_18c;
	char *char_pointer;
	uint32_t pass1_check[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	uint32_t pass2_check_a[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	uint32_t pass2_check_b[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	uint32_t pass3_check_a[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	uint32_t pass3_check_b[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	uint32_t local_a8[32];
	char valid_chars[] = "0123456789abcdef";	// 0x3736353433323130; // 0x6665646362613938;

	bVar8 = 0;
	if (argc == 2) {
		flag = argv[1];

		printf("input %s\n", flag);

// check length and flag format

		flag_len = strlen(flag);

		printf("input length %x\n", (unsigned int) flag_len);
		if (flag_len != 0x27) {
			puts("incorrect length != 0x27 (39)");
			exit(0);
		}
		iVar2 = memcmp(flag, "TWCTF{", 6);
		if ((iVar2 != 0) || (flag[0x26] != '}')) {
			puts("incorrect 2 flag must be TWCTF{ }");
			exit(0);
		}

//pass1
//check that input has the correct number of 0's .. F's:
/*
0  3  3
1  2  2
2  2  2
3  0  0
4  3  3
5  2  2
6  1  1
7  3  3
8  3  3
9  1  1
a  1  1
b  3  3
c  1  1
d  2  2
e  2  2
f  3  3
try: TWCTF{00011224445567778889abbbcddeefff} to pass this check
*/

		loop_counter1 = 0;

		while (char_pointer = flag, loop_counter1 < 16) {
			while (pcVar5 = strchr(char_pointer, (int) *(char *) ((long) &valid_chars + (long) loop_counter1)), pcVar5 != (char *) 0x0) {
				//*(int *) ((long) &pass1_check + (long) loop_counter1 * 4) = *(int *) ((long) &pass1_check + (long) loop_counter1 * 4) + 1;
				pass1_check[loop_counter1] += 1;
				char_pointer = pcVar5 + 1;
			}
			loop_counter1 = loop_counter1 + 1;
		}

		for (int i = 0; i < 16; i++)
			printf("%c %2d %2d\n", valid_chars[i], pass1_check[i],
				   DAT_00400f00[i]);

		printf("try: TWCTF{");
		for (int i = 0; i < 16; i++)
			for (int j = 0; j < DAT_00400f00[i]; j++)
				printf("%c", valid_chars[i]);
		printf("}\n");

		printf("{");
		for (int i = 0; i < 16; i++)
			for (int j = 0; j < DAT_00400f00[i]; j++)
				printf("%c, ", valid_chars[i]);
		printf("}\n");

		// 176243969782620087828480000000 permutations

		iVar2 = memcmp(&pass1_check, &DAT_00400f00, 64);
		if (iVar2 != 0) {
			puts("incorrect 3 does not have the correct number of each 0..f");
			exit(0);
		}

//pass2
//first check: col sum array
/*
0 1 2 3
4 5 6 7
8 9 10 11
12 13 14 15
16 17 18 19
20 21 22 23
24 25 26 27
28 29 30 31
*/
//2nd check: col xor

		loop_counter2 = 0;
		while (loop_counter2 < 8) {
			local_1b0 = 0;
			local_1ac = 0;
			local_1a8 = 0;
			while (local_1a8 < 4) {
				local_1b0 = local_1b0 + (int) flag[(long) local_1a8 + (long) (loop_counter2 << 2) + 6];
				local_1ac = local_1ac ^ (int) flag[(long) local_1a8 + (long) (loop_counter2 << 2) + 6];
				local_1a8 = local_1a8 + 1;
			}

			//*(int *) ((long) &pass2_check_a + (long) loop_counter2 * 4) = local_1b0;
			pass2_check_a[loop_counter2] = local_1b0;

			//*(unsigned int *) ((long) &pass2_check_b + (long) loop_counter2 * 4) = local_1ac;
			pass2_check_b[loop_counter2] = local_1ac;

			loop_counter2 = loop_counter2 + 1;
		}

		iVar2 = memcmp(&pass2_check_a, &DAT_00400f40, 32);
		if ((iVar2 != 0)
			|| (iVar2 =
				memcmp(&pass2_check_b, &DAT_00400f60, 32), iVar2 != 0)) {
			puts("incorrect 4");
			exit(0);
		}


//pass3
//first check: row sum, sum every 8th starting from 0-7
/*
0 8 16 24
1 9 17 25
2 10 18 26
3 11 19 27
4 12 20 28
5 13 21 29
6 14 22 30
7 15 23 31
*/
//2nd check: row xor 

		loop_counter3 = 0;
		while (loop_counter3 < 8) {
			local_1a0 = 0;
			local_19c = 0;
			local_198 = 0;
			while (local_198 < 4) {
				local_1a0 = local_1a0 + (int) flag[(long) (local_198 << 3) + (long) loop_counter3 + 6];
				local_19c = local_19c ^ (int) flag[(long) (local_198 << 3) + (long) loop_counter3 + 6];
				local_198 = local_198 + 1;
			}
			//*(int *) ((long) &pass3_check_a + (long) loop_counter3 * 4) = local_1a0;
			pass3_check_a[loop_counter3] = local_1a0;

			//*(unsigned int *) ((long) &pass3_check_b + (long) loop_counter3 * 4) = local_19c;
			pass3_check_b[loop_counter3] = local_19c;

			loop_counter3 = loop_counter3 + 1;
		}

		iVar2 = memcmp(&pass3_check_a, &DAT_00400fa0, 32);
		if ((iVar2 != 0)
			|| (iVar2 =
				memcmp(&pass3_check_b, &DAT_00400f80, 32), iVar2 != 0)) {
			puts("incorrect 5");
			exit(0);
		}


// check for
// digits or alpha check 0x80 if alpha, 0xff is digit
//
// TWCTF{  9 9  9 99  99 9  9  999  999  }
// TWCTF{  8 8  8 88  88 8  8  888  888  }
// TWCTF{  7 7  7 77  77 7  7  777  777  }
// TWCTF{  6 6  6 66  66 6  6  666  666  }
// TWCTF{f 5f5  5f55ff55f5 f5ff555 f555f }
// TWCTF{e 4e4  4e44ee44e4 e4ee444 e444e }
// TWCTF{d 3d3  3d33dd33d3 d3dd333 d333d }
// TWCTF{c 2c2  2c22cc22c2 c2cc222 c222c }
// TWCTF{b 1b1  1b11bb11b1 b1bb111 b111b }
// TWCTF{a 0a0  0a00aa00a0 a0aa000 a000a }
//
// TWCTF{.f...87..........2.......4.....5}


		lVar6 = 0x10;
		puVar7 = local_a8;
		while (lVar6 != 0) {
			lVar6 = lVar6 + -1;
			*puVar7 = 0;
			puVar7 = puVar7 + (ulong) bVar8 *0x1ffffffffffffffe + 1;
		}
		local_194 = 0;
		while (local_194 < 0x20) {
			cVar1 = flag[(long) local_194 + 6];
			if ((cVar1 < '0') || ('9' < cVar1)) {
				if ((cVar1 < 'a') || ('f' < cVar1)) {
					*(uint32_t *) ((long) local_a8 + (long) local_194 * 4) = 0;
				} else {
					*(uint32_t *) ((long) local_a8 + (long) local_194 * 4) = 0x80;
				}
			} else {
				*(uint32_t *) ((long) local_a8 + (long) local_194 * 4) =
					0xff;
			}
			local_194 = local_194 + 1;
		}

		iVar2 = memcmp(local_a8, &DAT_00400fc0, 0x80);
		if (iVar2 != 0) {
			puts("incorrect 6");
			exit(0);
		}

// check for
// sum of the chars in position 6,8,.... 36 = 0x488 (1160)
// TWCTF{.f...87..........2.......4.....5}
// TWCTF{^f^.^8^.^.^.^.^.^2^.^.^.^4^.^.^5}

		local_190 = 0;
		local_18c = 0;
		while (local_18c < 16) {
			local_190 = local_190 + flag[(local_18c + 3) * 2];
			local_18c = local_18c + 1;
		}

		if (local_190 != 0x488) {
			puts("incorrect 7");
			exit(0);
		}

// check for
// TWCTF{.f...87..........2.......4.....5}

		if ((((flag[0x25] != '5') || (flag[7] != 'f'))
			 || (flag[0xb] != '8'))
			||
			(((flag[0xc] != '7' || (flag[0x17] != '2'))
			  || (flag[0x1f] != '4')))) {
			puts("incorrect 8");
			exit(0);
		}

		printf("Correct: %s\n", flag);
		uVar3 = 0;
	} else {
		fwrite("./bin flag_is_here", 1, 0x12, stderr);
		uVar3 = 1;
	}

	return uVar3;
}
