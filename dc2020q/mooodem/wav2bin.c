//https://www.daniweb.com/programming/software-development/threads/340334/reading-audio-file-in-c

#include <stdio.h>
#include "wav.h"

int main(int argc, char **argv)
{
	int16_t *samples = NULL;
	float point;
	FILE *ofp;

	if(argc != 3) {
		fprintf(stderr,"\nUsage: %s input.wav output.bin\n\n",argv[0]);
		return 1;
	}

	if ((ofp = fopen(argv[2], "wb")) == NULL) {
		fprintf(stderr,"\nCannot open: %s\n\n",argv[1]);
		return 1;
	}

	wavread(argv[1], &samples);
	for(int i=0;i<header->datachunk_size;i++) {
		point = samples[i] / 32767.0;
		fwrite(&point, 4, 1, ofp);
	}

	free(header);
	free(samples);

	return(0);
}
