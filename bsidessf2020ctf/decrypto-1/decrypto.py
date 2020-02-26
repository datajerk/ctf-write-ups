import sys
import json
import hashlib


class Crypto:

    def __init__(self, key):
        if not isinstance(key, bytes):
            raise TypeError('key must be of type bytes!')
        self.key = key
        self._buf = bytes()
        self._out = open("/dev/stdout", "wb")

    def _extend_buf(self):
        self._buf += self.key

    def get_bytes(self, nbytes):
        while len(self._buf) < nbytes:
            self._extend_buf()
        ret, self._buf = self._buf[:nbytes], self._buf[nbytes:]
        return ret

    def encrypt(self, buf):
        if not isinstance(buf, bytes):
            raise TypeError('buf must be of type bytes!')
        stream = self.get_bytes(len(buf))
        return bytes(a ^ b for a, b in zip(buf, stream))

    def set_outfile(self, fname):
        self._out = open(fname, "wb")

    def encrypt_file(self, fname):
        buf = open(fname, "rb").read()
        self._out.write(self.encrypt(buf))


class JSONCrypto(Crypto):

    def encrypt_file(self, fname):
        buf = open(fname, "r").read().strip()
        h = hashlib.sha256(buf.encode('utf-8')).hexdigest()
        data = {
                "filename": fname,
                "hash": h,
                "plaintext": buf,
        }
        outbuf = json.dumps(data, sort_keys=True, indent=4)
        self._out.write(self.encrypt(outbuf.encode("utf-8")))


def main(argv):
    if len(argv) not in (3, 4):
        print("%s <key> <infile> [outfile]" % sys.argv[0])
        return
    argv.pop(0)
    key = argv.pop(0)
    inf = argv.pop(0)
    crypter = JSONCrypto(key.encode("utf-8"))
    if sys.argv:
        crypter.set_outfile(argv.pop(0))
    crypter.encrypt_file(inf)


if __name__ == '__main__':
    main(sys.argv)
