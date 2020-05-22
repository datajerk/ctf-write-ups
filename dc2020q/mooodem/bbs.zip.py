#!/usr/bin/python3 

from pwn import *
import os

def getsome(filename,p,n,d):
	c = 0
	if os.path.exists(filename):
		os.remove(filename)
	f = open(filename,'wb+')
	while c < n:
		_ = p.recv(4096)
		c += len(_)
		f.write(_)
		print('.',end='')
		if d == 1:
			print(c, len(_))
	print()
	f.close()
	return

p = remote('mooodem.challenges.ooo', 5000)

os.system('/bin/echo -e "datajerk\nL\nF\n2" | minimodem -t -8 -f in1.wav 1200 ; ./wav2bin in1.wav in1.bin')
r = open('in1.bin','rb').read()
p.send(r)

getsome('bout4.bin',p,878051716,0)

'''
./bin2wav bout4.bin bout4.wav; minimodem -r -8 -f bout4.wav 1200 | grep "00 00 00" foo | sed 's/ //g' | xxd -r -p >bbs.zip
'''
