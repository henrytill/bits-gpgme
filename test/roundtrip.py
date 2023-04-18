import tempfile
import unittest
from enum import IntEnum
from pathlib import Path

from _cipher_cffi import ffi, lib

GNUPGHOME = "./example/gnupg"
FINGERPRINT = "74EF511A371C136C"
INPUT = "Hello, world!\n"


class Result(IntEnum):
    SUCCESS = 0
    FAILURE = 1


def cstr(string: str):
    return ffi.new("char[]", string.encode("ASCII"))


def pathstr(path: Path):
    return ffi.new("char[]", path.as_posix().encode("ASCII"))


def encrypt(fingerprint: str, input: str, output_file: Path, gnupghome: Path) -> int:
    input_len = len(input)
    with open(output_file, "wb") as output:
        return lib.cipher_encrypt(cstr(fingerprint), cstr(input), input_len, output, pathstr(gnupghome))


def decrypt(fingerprint: str, input_file: Path, output_file: Path, gnupghome: Path) -> int:
    with open(input_file, "rb") as input:
        with open(output_file, "wb") as output:
            return lib.cipher_decrypt(cstr(fingerprint), input, output, pathstr(gnupghome))


def read(file: Path) -> bytes:
    with open(file, "rb") as f:
        return f.read()


def roundtrip(fingerprint: str, input: str, gnupghome: Path, ciphertext_file: Path, output_file: Path) -> str:
    result = encrypt(fingerprint, input, ciphertext_file, gnupghome)
    if result != Result.SUCCESS:
        raise Exception("encrypt failed")
    result = decrypt(fingerprint, ciphertext_file, output_file, gnupghome)
    if result != Result.SUCCESS:
        raise Exception("decrypt failed")
    return read(output_file).decode("ASCII")


class TestRoundtrip(unittest.TestCase):
    def test_roundtrip_success(self):
        with tempfile.NamedTemporaryFile(suffix=".asc", delete=True) as ciphertext:
            with tempfile.NamedTemporaryFile(suffix=".txt", delete=True) as plaintext:
                ciphertext_file = Path(ciphertext.name)
                plaintext_file = Path(plaintext.name)
                output: str = roundtrip(FINGERPRINT, INPUT, Path(GNUPGHOME), ciphertext_file, plaintext_file)
                self.assertEqual(output, INPUT, "should roundtrip")


if __name__ == "__main__":
    unittest.main()
