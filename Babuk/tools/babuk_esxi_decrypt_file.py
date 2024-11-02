# MIT License
#
# Copyright (c) 2023-2024 Andrey Zhdanov (rivitna)
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
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
import sosemanuk


RANSOM_EXT = '.babyk'


MAX_ENC_SIZE = (0x20000000 // 0xA00000 + 1) * 0xA00000


# x25519
X25519_KEY_SIZE = 32

# Sosemanuk
SOSEMANUK_KEY_SIZE = 32

# Metadata
METADATA_SIZE = X25519_KEY_SIZE


ENC_BLOCK_SIZE = 0x100000


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        pub_key_data = f.read(METADATA_SIZE)

        # Derive x25519 shared secret
        priv_key = X25519PrivateKey.from_private_bytes(priv_key_data)
        pub_key = X25519PublicKey.from_public_bytes(pub_key_data)
        shared_secret = priv_key.exchange(pub_key)

        # Derive Sosemanuk encryption key
        key = hashlib.sha256(shared_secret).digest()

        # Remove metadata
        f.seek(-METADATA_SIZE, 2)
        f.truncate()

        cipher = sosemanuk.Sosemanuk(key)

        f.seek(0)

        total_read = 0

        while total_read < MAX_ENC_SIZE:

            enc_data = f.read(ENC_BLOCK_SIZE)
            if enc_data == b'':
                break

            data = cipher.decrypt(enc_data)

            bytes_read = len(enc_data)
            total_read += bytes_read

            f.seek(-bytes_read, 1)
            f.write(data)
        
    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./privkey.bin', 'rb') as f:
    priv_key_data = f.read()

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
