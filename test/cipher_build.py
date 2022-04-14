from cffi import FFI
import re


def read_header_content(path: str):
    ret = ""
    with open(path) as file:
        for line in file:
            if not re.match(r"^#.+$", line):
                ret += line
    return ret


def main():
    ffibuilder = FFI()
    header_content = read_header_content("../src/cipher.h")
    ffibuilder.cdef(header_content)
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
