from cffi import FFI
import re


def readhdr(path: str):
    ret = ""
    with open(path) as file:
        for line in file:
            if not re.match(r"^#.+$", line):
                ret += line
    return ret


def main():
    ffibuilder = FFI()
    hdr = readhdr("../src/cipher.h")
    ffibuilder.cdef(hdr)
    ffibuilder.set_source("_cipher_cffi",
                          """
                          #include "cipher.h"
                          """,
                          include_dirs=['../src'],
                          library_dirs=['./src'],
                          libraries=['cipher'])
    ffibuilder.compile(verbose=True)


if __name__ == "__main__":
    main()
