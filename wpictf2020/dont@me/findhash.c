#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
 
int main()
{
	unsigned int i,j,ret;
	FILE *f;
	unsigned char buf[70];
	unsigned char result[MD5_DIGEST_LENGTH];

	f = fopen("shellcode","rb");
	ret = fread(buf,65,1,f);
	fclose(f);
	buf[69]=buf[70]=0;

	for(i=0;i<(1 << 31);i++) {
		buf[65]=i % 0xff;
		buf[66]=(i >> 8) & 0xff;
		buf[67]=(i >> 16) & 0xff;
		buf[68]=(i >> 24) & 0xff;
 
		MD5(buf, 70, result);

		if(result[0] != 0x79 || result[1] != 0xfc || result[2] != 0x00)
			continue;

		for(j = 0; j < MD5_DIGEST_LENGTH; j++)
			printf("%02x", result[j]);
		printf("\n");

		f = fopen("newcode","wb");
		ret = fwrite(buf,70,1,f);
		fclose(f);

		break;
	}

	return EXIT_SUCCESS;
}
