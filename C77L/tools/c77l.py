# MIT License
#
# Copyright (c) 2025-2026 Andrey Zhdanov (rivitna)
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

import io
import struct
from typing import Callable
import binascii
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


ENC_MARKER1 = b'EncryptedByC77L'
ENC_MARKER2 = b'LockedByX77C'
ENC_MARKER3 = b'EncryptRansomware'
ENC_MARKER4 = b'\xAB\xBC\xCD\xDE\xEF\xF0'


# Session key field delimiter
SKEY_FIELD_DELIM = ' : '


# HKDF info
HKDF_INFO = b'x25519-aes256-key-wrap'


# X25519
X25519_KEY_SIZE = 32

# AES
KEY_SIZE = 32
IV_SIZE = 16
AES_BLOCK_SIZE = 16


# Decryption function type
DecryptFunc = Callable[[bytes, bytes], bytes]


def is_file_encrypted(filename: str, enc_marker: bytes) -> bool:
    """Check if file is encrypted"""

    with io.open(filename, 'rb') as f:
        # Read marker
        marker = f.read(len(enc_marker))

    # Check marker
    return (marker == enc_marker)


def load_session_keys(filename: str) -> dict:
    """Load session keys"""

    # Read session key lines
    with io.open(filename, 'rt') as f:
        key_lines = f.read().splitlines()

    # Parse key lines
    keys = {}
    for s in key_lines:
        fields = s.split(SKEY_FIELD_DELIM, 2)
        if len(fields) != 2:
            continue
        keys[binascii.unhexlify(fields[0])] = binascii.unhexlify(fields[1])
    return keys


def save_session_keys(filename: str, session_keys: dict) -> None:
    """Save session keys"""

    with io.open(filename, 'wt') as f:
        # Save key lines
        for enc_key, key in session_keys.items():
            f.write(binascii.hexlify(enc_key).decode() +
                    SKEY_FIELD_DELIM +
                    binascii.hexlify(key).decode())


def extract_enc_session_key(filename: str,
                            enc_marker: bytes) -> bytes | None:
    """Extract encrypted session key"""

    with io.open(filename, 'rb') as f:

        # Read header
        header_size = len(enc_marker) + 1 + 8
        header = f.read(header_size)
        if len(header) != header_size:
            return None

        # Check marker
        marker = header[:len(enc_marker)]
        if marker != enc_marker:
            return None

        enc_skey_size, = struct.unpack_from('<Q', header,
                                            len(enc_marker) + 1)

        # Read encrypted session key data
        enc_skey = f.read(enc_skey_size)
        if len(enc_skey) != enc_skey_size:
            return None

        return enc_skey


def aes_ctr_decrypt(enc_data: bytes, key: bytes) -> bytes:
    """AES CTR decrypt data"""

    iv = enc_data[:IV_SIZE]
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(enc_data[IV_SIZE:]) + decryptor.finalize()


def aes_cbc_decrypt(enc_data: bytes, key: bytes) -> bytes:
    """AES CBC decrypt data"""

    iv = enc_data[:IV_SIZE]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(enc_data[IV_SIZE:]) + decryptor.finalize()

    # PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def decrypt_session_key1(enc_session_key_data: bytes,
                         master_priv_key_data: bytes) -> bytes | None:
    """
    Decrypt session key (RSA OAEP).
    EncryptedByC77L
    LockedByX77C
    EncryptRansomware
    ABBCCDDEEFF0 v1
    """

    priv_key = serialization.load_der_private_key(master_priv_key_data,
                                                  password=None)
    try:
        return priv_key.decrypt(enc_session_key_data,
                                OAEP(mgf=MGF1(algorithm=hashes.SHA1()),
                                     algorithm=hashes.SHA1(),
                                     label=None))

    except ValueError:
        return None


def decrypt_session_key2(enc_session_key_data: bytes,
                         master_priv_key_data: bytes) -> bytes:
    """
    Decrypt session key (X25519 - AES CTR).
    ABBCCDDEEFF0 v2
    """

    pub_key_data = enc_session_key_data[:X25519_KEY_SIZE]
    enc_data = enc_session_key_data[X25519_KEY_SIZE:]

    # Derive x25519 shared secret
    m_priv_key = X25519PrivateKey.from_private_bytes(master_priv_key_data)
    pub_key = X25519PublicKey.from_public_bytes(pub_key_data)
    shared_secret = m_priv_key.exchange(pub_key)

    # Derive encryption key (HKDF)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None,
                info=HKDF_INFO)
    key = hkdf.derive(shared_secret)

    # AES CTR decrypt data
    return aes_ctr_decrypt(enc_data, key)


if __name__ == '__main__':
    #
    # Main
    #
    import sys
    import os

    if len(sys.argv) != 2:
        print('Usage:', os.path.basename(sys.argv[0]), 'filename')
        sys.exit(0)

    filename = sys.argv[1]

    for enc_marker in [ENC_MARKER1, ENC_MARKER2, ENC_MARKER3, ENC_MARKER4]:
        # Check if file is encrypted
        if is_file_encrypted(filename, enc_marker):
            break
    else:
        print('Error: File not encrypted or damaged')
        sys.exit(1)

    # Extract encrypted session key from encrypted file
    enc_session_key = extract_enc_session_key(filename, enc_marker)
    if not enc_session_key:
        print('Error: Unable to extract encrypted session key')
        sys.exit(1)

    new_filename = filename + '.enckey'
    with io.open(new_filename, 'wt') as f:
        f.write(binascii.hexlify(enc_session_key).decode() + '\n')
