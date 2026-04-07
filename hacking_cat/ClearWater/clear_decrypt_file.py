# MIT License
#
# Copyright (c) 2026 Andrey Zhdanov (rivitna)
# https://github.com/rivitna
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import sys
import io
import os
import shutil
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import ChaCha20


RANSOM_EXT = '.clear'


# "MYEK"
ENC_MARKER = 0x4B45594D


# ChaCha20
CHACHA_KEY_SIZE = 32
CHACHA_NONCE_SIZE = 8


# Footer
FOOTER_NONCE_SIZE = 12
FOOTER_ENCMARKER_POS = FOOTER_NONCE_SIZE
FOOTER_ENCKEYDATA_POS = FOOTER_ENCMARKER_POS + 4 + 4


PART_MIN_FILE_SIZE = 0x500000000
PART_MAX_ENC_SIZE = 0x280000000

ENC_BLOCK_SIZE = 0x800000


SENTINEL_SIZE = 16


def rsa_decrypt(enc_data: bytes, priv_key: RSA.RsaKey) -> bytes | None:
    """RSA PKCS#1 v1.5 decrypt data"""

    sentinel = os.urandom(SENTINEL_SIZE)
    cipher = PKCS1_v1_5.new(priv_key)
    try:
        data = cipher.decrypt(enc_data, sentinel)
    except ValueError:
        return None
    if data == sentinel:
        return None
    return data


def decrypt_file(filename: str, priv_key: RSA.RsaKey) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        rsa_key_size = priv_key.size_in_bytes()
        footer_size = FOOTER_ENCKEYDATA_POS + rsa_key_size

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < footer_size:
            return False

        # Read footer data
        f.seek(-footer_size, 2)
        footer = f.read(footer_size)

        # Check encryption marker
        marker, enc_key_data_size = struct.unpack_from('<LL', footer,
                                                       FOOTER_ENCMARKER_POS)
        if marker != ENC_MARKER:
            print('marker: Failed')
            return False

        print('marker: OK')

        if enc_key_data_size != rsa_key_size:
            print('private key: Failed')
            return False

        nonce = footer[:CHACHA_NONCE_SIZE]
        enc_key_data = footer[FOOTER_ENCKEYDATA_POS:]

        # Decrypt key
        key = rsa_decrypt(enc_key_data, priv_key)
        if not key:
            print('private key: Failed')
            return False

        print('private key: OK')

        orig_file_size = file_size - footer_size
        print('original file size:', orig_file_size)

        if orig_file_size >= PART_MIN_FILE_SIZE:
            enc_size = PART_MAX_ENC_SIZE
        else:
            enc_size = orig_file_size
        print('encrypted data size:', enc_size)

        # Decrypt data
        cipher = ChaCha20.new(key=key, nonce=nonce)

        f.seek(0)

        pos = 0
        while pos < enc_size:

            block_size = min(enc_size - pos, ENC_BLOCK_SIZE)
            enc_data = f.read(block_size)
            bytes_read = len(enc_data)
            if bytes_read == 0:
                break

            data = cipher.decrypt(enc_data)

            f.seek(-bytes_read, 1)
            f.write(data)

            pos += bytes_read

        # Remove footer
        f.truncate(orig_file_size)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./rsa_privkey.pem', 'rb') as f:
    priv_key_data = f.read()

# Import RSA private key
priv_key = RSA.import_key(priv_key_data)

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
