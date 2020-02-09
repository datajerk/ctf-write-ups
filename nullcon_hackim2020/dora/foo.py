#!/usr/bin/env python

# props:
# https://stackoverflow.com/questions/7853628/how-do-i-find-an-image-contained-within-an-image
# https://opencv-python-tutroals.readthedocs.io/en/latest/py_tutorials/py_imgproc/py_template_matching/py_template_matching.html#template-matching

from pwn import *
import base64
from PIL import Image
import numpy as np
import cv2

im = Image.open("dora.png")
px = im.load()
print(px[0,0][0])

im = im.convert('RGBA')
data = np.array(im)
r, g, b, a = data.T

bg = (r == px[0,0][0]) & (g == px[0,0][1]) & (b == px[0,0][2])
data[...,:-1][bg.T] = (255, 0, 0)

im = Image.fromarray(data)

im.save("foo2.png","PNG")

notdora = ["dora-bag.png","dora-cow.png","dora-dino.png","dora-fox.png","dora-monkey.png"]
method = cv2.TM_SQDIFF_NORMED

large_image = cv2.cvtColor(np.array(im), cv2.COLOR_RGB2BGR)

for i in notdora:
	small_image = cv2.imread(i)
	result = cv2.matchTemplate(large_image, small_image, method)
	mn,_,mnLoc,_ = cv2.minMaxLoc(result)
	MPx,MPy = mnLoc
	trows,tcols = small_image.shape[:2]
	cv2.rectangle(large_image, (MPx-17,MPy-17),(MPx+tcols+17,MPy+trows+17),(0,0,255),-1)

cv2.imwrite('foo3.png',large_image)

q = [0,0,0,0,0]
border=5

q[0] = np.zeros((360-(border*2),360-(border*2),3),np.uint8)
q[0][:] = (0,0,255)

i=0
cv2.imwrite('q' + str(i) + '.png',q[i])

q[1] = large_image[0+border:360-border,360+border:720-border]
q[2] = large_image[0+border:360-border,0+border:360-border]
q[3] = large_image[360+border:720-border,0+border:360-border]
q[4] = large_image[360+border:720-border,360+border:720-border]

for i in range(1,5):
	cv2.imwrite('q' + str(i) + '.png',q[i])

for i in range(1,5):
	diff = cv2.subtract(q[0],q[i])
	b, g, r = cv2.split(diff)
	if cv2.countNonZero(b) != 0 or cv2.countNonZero(g) != 0 or cv2.countNonZero(r) != 0:
		dora=i
		break

print dora
