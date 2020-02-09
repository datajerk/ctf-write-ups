#!/usr/bin/env python

from pwn import *
import base64
from PIL import Image
import numpy as np
import cv2

p = remote('misc.ctf.nullcon.net',8000)
p.recvuntil('Where\'s Dora? 1 for upper right, 2 for upper left, 3 for lower left, 4 for lower right',timeout=1)

count=0
doralog = open("dora.log","w")

while 1:
	count=count+1
	p.recvline()
	image = p.recvline()

	if image.strip() == 'No flag for you':
		sys.exit(1)

	# save it for debug
	f = open("dora.png","w")
	f.write(base64.decodestring(image))
	f.close()

	# read image
	im = Image.open("dora.png")
	# get pixels
	px = im.load()

	# create cv image
	im = im.convert('RGBA')
	data = np.array(im)
	r, g, b, a = data.T

	# change bg to red
	bg = (r == px[0,0][0]) & (g == px[0,0][1]) & (b == px[0,0][2])
	data[...,:-1][bg.T] = (255, 0, 0)

	# new image with background red
	im = Image.fromarray(data)

	# the furries
	notdora = ["dora-bag.png","dora-cow.png","dora-dino.png","dora-fox.png","dora-monkey.png"]
	method = cv2.TM_SQDIFF_NORMED

	large_image = cv2.cvtColor(np.array(im), cv2.COLOR_RGB2BGR)

	# wipe out furries
	for i in notdora:
		small_image = cv2.imread(i)
		result = cv2.matchTemplate(large_image, small_image, method)
		mn,_,mnLoc,_ = cv2.minMaxLoc(result)
		MPx,MPy = mnLoc
		trows,tcols = small_image.shape[:2]
		#cv2.rectangle(large_image, (MPx,MPy),(MPx+tcols,MPy+trows),(0,0,255),-1)
		#cv2.rectangle(large_image, (MPx-2,MPy-2),(MPx+tcols+4,MPy+trows+4),(0,0,255),-1)
		# needed larger rect
		cv2.rectangle(large_image, (MPx-17,MPy-17),(MPx+tcols+17,MPy+trows+17),(0,0,255),-1)

	# quads
	q = [0,0,0,0,0]
	border=5

	# blank red compare image
	q[0] = np.zeros((360-(border*2),360-(border*2),3),np.uint8)
	q[0][:] = (0,0,255)

	# quad up the image without furries
	q[1] = large_image[0+border:360-border,360+border:720-border]
	q[2] = large_image[0+border:360-border,0+border:360-border]
	q[3] = large_image[360+border:720-border,0+border:360-border]
	q[4] = large_image[360+border:720-border,360+border:720-border]

	# search for no match
	for i in range(1,5):
		diff = cv2.subtract(q[0],q[i])
		b, g, r = cv2.split(diff)
		if cv2.countNonZero(b) != 0 or cv2.countNonZero(g) != 0 or cv2.countNonZero(r) != 0:
			dora=i
			break

	line = "count: " + str(count) + " " + "dora: " + str(dora)
	doralog.write(line + '\n')
	print line
	p.sendline(str(dora))
