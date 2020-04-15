# BSidesSF 2020 CTF

## decrypto-2

> [Kerckhoffs's principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle) states that "A cryptosystem should be secure even if everything about the system, except the key, is public knowledge." So here's our unbreakable cipher.
>
> (author: matir)
>
> [`flag.svg.enc`](flag.svg.enc)<br />[`decrypto.py`](decrypto.py)

Tags: _crypto_

### Analysis

A quick scan of [`decrypto.py`](decrypto.py) reveals a simple XOR cipher (last line):

```
def encrypt(self, buf):
    if not isinstance(buf, bytes):
        raise TypeError('buf must be of type bytes!')
    stream = self.get_bytes(len(buf))
    return bytes(a ^ b for a, b in zip(buf, stream))
```

#### Perform a quick test:

Create a file `foo` with the contents `ABCD` and then type:

```
python decrypto.py 1234 foo bar
```

#### Instrument the code and print out `buf` and `stream`:

Before `return bytes...`:

`buf` = `b'ABCD\n'` and the key (`stream`) = `b'\xf7\x00\x98U\n'`

The output file `bar` is just `buf` XOR `stream` byte for byte.  However, unlike [decrypto-1](https://github.com/datajerk/ctf-write-ups/tree/master/bsidessf2020ctf/decrypto-1) the key is not just a simple repeating pattern (well it is, after examining the code):

```
def _extend_buf(self):
    self._blk = hashlib.sha256(
            self._blk + struct.pack('<I', self._blkid)).digest()
    self._blkid += 1
    self._buf += self._blk
```

The derived key is constructed by calling `_extend_buf` repeatedly until the key is at least as long as the input file.

The derived key initial round starts with the user provided key appended with a 32-bit little endian `0` that is then SHA256'd.  The next round appends a 32-bit little endian `1` to the previous hash, and SHA256's that, and then appends that to the derived key, and so on:

`derived key = sha256(key+0) + sha256(sha256(key+0)+1) + sha256(sha256(sha256(key+0)+1)+2) + ...`

> NOTE: Above `+` is _append bytes_.

Like other XOR challenges, to decrypt the _ciphertext_ we need to know either the _key_ or the _plaintext_ (to then derive the _key_).

The only clue is the filename `flag.svg.enc`.  Assuming that this is a [Scalable Vector Graphics](https://en.wikipedia.org/wiki/Scalable_Vector_Graphics) file, in XML, starting with `<?xml version="1.0" encoding="UTF-8" standalone="no"?>`, then it should be possible to get the first hash with _SVG-Header XOR ciphertext_ that can be used to then generate the rest of the hashes and thus the derived key.

> NOTE: it is not necessary to actually know the users original key, only the first hash `sha256(key+0)`!

### Solve

```
#!/usr/bin/env python3

import hashlib
import struct

xml_header='<?xml version="1.0" encoding="UTF-8" standalone="no"?>'.encode("utf-8")
buf=open("flag.svg.enc", "rb").read()
hash=(bytes(a ^ b for a,b in zip(xml_header[:32], buf)))
key=hash

for i in range(int(len(buf) / 32) + 1):
    hash=hashlib.sha256(hash + struct.pack('<I', i+1)).digest()
    key+=hash

print(bytes(a ^ b for a, b in zip(buf, key)).decode("utf-8"))
```

Output:

```
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!-- Created with Inkscape (http://www.inkscape.org/) -->

<svg
   xmlns:dc="http://purl.org/dc/elements/1.1/"
   xmlns:cc="http://creativecommons.org/ns#"
   xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
   xmlns:svg="http://www.w3.org/2000/svg"
   xmlns="http://www.w3.org/2000/svg"
   xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd"
   xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
   width="245.58449mm"
   height="14.463888mm"
   viewBox="0 0 245.58449 14.463888"
   version="1.1"
   id="svg8"
   inkscape:version="0.92.4 (5da689c313, 2019-01-14)"
   sodipodi:docname="flag.svg">
  <defs
     id="defs2" />
  <sodipodi:namedview
     id="base"
     pagecolor="#ffffff"
     bordercolor="#666666"
     borderopacity="1.0"
     inkscape:pageopacity="0.0"
     inkscape:pageshadow="2"
     inkscape:zoom="0.98994949"
     inkscape:cx="363.66125"
     inkscape:cy="-5.9640273"
     inkscape:document-units="mm"
     inkscape:current-layer="layer1"
     showgrid="false"
     fit-margin-top="0"
     fit-margin-left="0"
     fit-margin-right="0"
     fit-margin-bottom="0"
     inkscape:window-width="1920"
     inkscape:window-height="1021"
     inkscape:window-x="0"
     inkscape:window-y="0"
     inkscape:window-maximized="1" />
  <metadata
     id="metadata5">
    <rdf:RDF>
      <cc:Work
         rdf:about="">
        <dc:format>image/svg+xml</dc:format>
        <dc:type
           rdf:resource="http://purl.org/dc/dcmitype/StillImage" />
        <dc:title></dc:title>
      </cc:Work>
    </rdf:RDF>
  </metadata>
  <g
     inkscape:label="Layer 1"
     inkscape:groupmode="layer"
     id="layer1"
     transform="translate(91.741086,-130.11192)">
    <text
       xml:space="preserve"
       style="font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:14.11111069px;line-height:6.61458302px;font-family:Comfortaa;-inkscape-font-specification:Comfortaa;font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;text-align:center;letter-spacing:0px;word-spacing:0px;writing-mode:lr-tb;text-anchor:middle;fill:#000000;fill-opacity:1;stroke:none;stroke-width:0.26458332px;stroke-linecap:butt;stroke-linejoin:miter;stroke-opacity:1"
       x="30.994047"
       y="141.2738"
       id="text817"><tspan
         sodipodi:role="line"
         id="tspan815"
         x="30.994049"
         y="141.2738"
         style="stroke-width:0.26458332px">CTF{but_even_I_couldnt_break_IT}</tspan></text>
  </g>
</svg>
```

Flag: `CTF{but_even_I_couldnt_break_IT}`

It was not necessary to actually render the SVG, but for the lulz:

![](./flag.svg)

