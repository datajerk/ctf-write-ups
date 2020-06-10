# Really Awesome CTF 2020

## BR.MOV

> 400
>
> [https://youtu.be/zi3pLOaUUXs](https://youtu.be/zi3pLOaUUXs)
>
> Author: Bottersnike

Tags: _video_ _barcode_ _ffmpeg_ _zbarimg_

## Summary

Video of barcodes with white noise background and a dude saying a number for each barcode (not in series).


## Solve

```
#!/bin/bash

youtube-dl 'https://youtu.be/zi3pLOaUUXs'
ffmpeg -i BR.MOV-zi3pLOaUUXs.mkv -r 60 foo%04d.png
for i in *.png; do zbarimg $i; done | tee foo.txt
for i in $(awk -F: '{print $NF}' foo.txt | uniq | grep -v '^7+')
do
	index=$(echo $i | cut -c 1-1)
	data=$(echo $i | cut -c 2-)
	echo $data | cut -c $index-$index
done | xargs | sed 's/ //g'
```

The above just rips the video from youtube, then uses `ffmpeg` to take some snaps of the frames.  `zbarimg` is then used to read each frame.  With the exception of one line (`7+`), then rest is good:

```
5WlndrAehA
8PdGSTvnaY
9zuPGubRMc
7cyqggztfa
6AqGoWfWwR
7JwvAOM{Px
4JIEbOEkws
5NDuG4sOeb
9chPBBYtfr
8iwkHVYpcf
7hVMGQe0xL
3vBdLvZLbB
2T3iNatxiU
5kNLb_eoyi
4AfAmLXyJo
4oFE4iSJmP
3ajdUBIXVe
4oAQnoJxEV
8SzMNoIa3j
9aaIBHbqls
2vsDNpidao
1}gfkrtfrm
```

It's easy to spot the `{` and `}` and _guess_ that the first number (also the number the dude says) is an index.


Output:

```
ractf{b4rc0d3_m4dn3ss}
```
