from _cipher_cffi import ffi, lib
import os
import unittest

GNUPGHOME = b"./example/gnupg"
FINGERPRINT = b"74EF511A371C136C"
INPUT = b"Hello, world!\n"
CIPHERTEXT_FILE = "ciphertext.asc"
OUTPUT_FILE = "output.txt"


def cstr(bytestring: bytes):
    return ffi.new("char[]", bytestring)


def encrypt(fingerprint: bytes, input: bytes, out_file: str, gnupghome: bytes):
    input_len = len(input)
    with open(out_file, "wb") as output:
        lib.cipher_encrypt(cstr(fingerprint), cstr(input), input_len, output, cstr(gnupghome))


def decrypt(fingerprint: bytes, in_file: str, out_file: str, gnupghome: bytes):
    with open(in_file, "rb") as input:
        with open(out_file, "wb") as output:
            lib.cipher_decrypt(cstr(fingerprint), input, output, cstr(gnupghome))


def read(file: str):
    with open(file, "rb") as f:
        data = f.readlines()
    return data


def roundtrip(fingerprint: bytes, input: bytes, gnupghome: bytes, ciphertext: str, output: str):
    encrypt(fingerprint, input, ciphertext, gnupghome)
    decrypt(fingerprint, ciphertext, output, gnupghome)
    ret = read(output)
    os.remove(ciphertext)
    os.remove(output)
    return ret


class TestRoundtrip(unittest.TestCase):
    def test_roundtrip_success(self):
        output = roundtrip(FINGERPRINT, INPUT, GNUPGHOME, CIPHERTEXT_FILE, OUTPUT_FILE)
        self.assertEqual(output[0], INPUT, "should roundtrip")


if __name__ == '__main__':
    unittest.main()
