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
