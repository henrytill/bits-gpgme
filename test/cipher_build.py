import re
import sys
from pathlib import Path

from cffi import FFI


def readhdr(path: Path) -> str:
    ret: str = ''
    with open(path) as file:
        for line in file:
            if not re.match(r'^#.+$', line):
                ret += line
    return ret


def main() -> None:
    target = sys.argv[1]
    ffibuilder = FFI()
    hdr = readhdr(Path('./src/cipher.h'))
    ffibuilder.cdef(hdr)
    ffibuilder.set_source(
        '_cipher_cffi',
        """
        #include "cipher.h"
        """,
        include_dirs=['./src'],
        library_dirs=['./.'],
        libraries=['cipher'],
    )
    ffibuilder.compile(target=target, verbose=False)


if __name__ == '__main__':
    main()
