#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void Write_WAVE(FILE * fptr, double *samples, long nsamples, int nfreq, int bits, double amp);

#define ABS(x) (((x) < 0) ? -(x) : (x))

int main(int argc, char **argv)
{

	FILE *ifp, *ofp;
	float point;
	double *samples = NULL;
	long i = 0, filelength = 0, sampleslength = 0;
	
	if(argc != 3) {
		fprintf(stderr,"\nUsage: %s input.bin samples.wav\n\n",argv[0]);
		return 1;
	}

	if ((ifp = fopen(argv[1], "rb")) == NULL) {
		fprintf(stderr,"\nCannot read: %s\n\n",argv[1]);
		return 1;
	}

	if ((ofp = fopen(argv[2], "wb")) == NULL) {
		fprintf(stderr,"\nCannot open: %s\n\n",argv[1]);
		return 1;
	}

	fseek(ifp, 0L, SEEK_END);
	filelength = ftell(ifp);
	rewind(ifp);

	samples = malloc(((filelength/4) + 1) * sizeof(double));

	while(fread(&point, 4, 1, ifp) == 1)
		samples[i++] = point;

	Write_WAVE(ofp,samples,i-1,48000,16,1.0);

	return 0;
}

void Write_WAVE(FILE * fptr, double *samples, long nsamples, int nfreq, int bits, double amp)
{
	unsigned short v;
	int i;
	unsigned long totalsize, bytespersec;
	double themin, themax, scale, themid;

	// Write the form chunk
	fprintf(fptr, "RIFF");
	totalsize = (bits / 8) * nsamples + 36;
	fputc((totalsize & 0x000000ff), fptr);	// File size
	fputc((totalsize & 0x0000ff00) >> 8, fptr);
	fputc((totalsize & 0x00ff0000) >> 16, fptr);
	fputc((totalsize & 0xff000000) >> 24, fptr);
	fprintf(fptr, "WAVE");
	fprintf(fptr, "fmt ");		// fmt_ chunk
	fputc(16, fptr);			// Chunk size
	fputc(0, fptr);
	fputc(0, fptr);
	fputc(0, fptr);
	fputc(1, fptr);				// Format tag - uncompressed
	fputc(0, fptr);
	fputc(1, fptr);				// Channels
	fputc(0, fptr);
	fputc((nfreq & 0x000000ff), fptr);	// Sample frequency (Hz)
	fputc((nfreq & 0x0000ff00) >> 8, fptr);
	fputc((nfreq & 0x00ff0000) >> 16, fptr);
	fputc((nfreq & 0xff000000) >> 24, fptr);
	bytespersec = (bits / 8) * nfreq;
	fputc((bytespersec & 0x000000ff), fptr);	// Average bytes per second
	fputc((bytespersec & 0x0000ff00) >> 8, fptr);
	fputc((bytespersec & 0x00ff0000) >> 16, fptr);
	fputc((bytespersec & 0xff000000) >> 24, fptr);
	fputc((bits / 8), fptr);		// Block alignment
	fputc(0, fptr);
	fputc(bits, fptr);			// Bits per sample
	fputc(0, fptr);
	fprintf(fptr, "data");
	totalsize = (bits / 8) * nsamples;
	fputc((totalsize & 0x000000ff), fptr);	// Data size
	fputc((totalsize & 0x0000ff00) >> 8, fptr);
	fputc((totalsize & 0x00ff0000) >> 16, fptr);
	fputc((totalsize & 0xff000000) >> 24, fptr);

	// Find the range
	themin = samples[0];
	themax = themin;
	for (i = 1; i < nsamples; i++) {
		if (samples[i] > themax)
			themax = samples[i];
		if (samples[i] < themin)
			themin = samples[i];
	}
	if (themin >= themax) {
		themin -= 1;
		themax += 1;
	}
	themid = (themin + themax) / 2;
	themin -= themid;
	themax -= themid;
	if (ABS(themin) > ABS(themax))
		themax = ABS(themin);
//  scale = amp * 32760 / (themax);
	scale = amp * ((bits == 16) ? 32760 : 124) / (themax);

	// Write the data
	for (i = 0; i < nsamples; i++) {
		if (bits == 16) {
			v = (unsigned short) (scale * (samples[i] - themid));
			fputc((v & 0x00ff), fptr);
			fputc((v & 0xff00) >> 8, fptr);
		} else {
			v = (unsigned char) (scale * (samples[i] - themid));
			fputc(v + 0x80, fptr);
		}
	}
}
