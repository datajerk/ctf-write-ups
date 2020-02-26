#include <stdio.h>

int main()
{
	char *s = "{\n    \"filename\": \"flag.txt\",\n    \"hash\": ";
	FILE *fp = fopen("flag.txt.enc","r");

	while(*s)
		putchar(*s++ ^ fgetc(fp));

	return 0;
}
