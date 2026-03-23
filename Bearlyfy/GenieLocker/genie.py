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

import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat
)
from Crypto.Cipher import ChaCha20_Poly1305
import salsa


# x25519
X25519_KEY_SIZE = 32

# XSalsa20-Poly1305
XSALSA20POLY1305_KEY_SIZE = 32
XSALSA20POLY1305_NONCE_SIZE = 24
XSALSA20POLY1305_TAG_SIZE = 16

# HSalsa
HSALSA_NONCE = 16 * b'\0'

# XChaCha20-Poly1305
XCHACHA20POLY1305_KEY_SIZE = 32
XCHACHA20POLY1305_NONCE_SIZE = 24
XCHACHA20POLY1305_TAG_SIZE = 16

# Curve25519XSalsa20Poly1305 box (Sodium)
CRYPTO_BOX_KEY_DATA_SIZE = X25519_KEY_SIZE + XSALSA20POLY1305_TAG_SIZE


def xchacha20poly1305_decrypt(enc_data: bytes,
                              key, nonce, tag: bytes) -> bytes | None:
    """Decrypt XChaCha20-Poly1305"""

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(enc_data, tag)
    except ValueError:
        return None


def xchacha20poly1305_decrypt2(enc_data: bytes,
                               key, nonce: bytes) -> bytes | None:
    """Decrypt XChaCha20-Poly1305"""

    if len(enc_data) < XCHACHA20POLY1305_TAG_SIZE:
        return None

    tag = enc_data[-XCHACHA20POLY1305_TAG_SIZE:]
    enc_data = enc_data[:-XCHACHA20POLY1305_TAG_SIZE]
    return xchacha20poly1305_decrypt(enc_data, key, nonce, tag)


def curve25519xsalsa20poly1305_decrypt(box_data: bytes,
                                       priv_key_data: bytes) -> bytes | None:
    """Decrypt Curve25519XSalsa20Poly1305 box (Sodium)"""

    if len(box_data) < CRYPTO_BOX_KEY_DATA_SIZE:
        return None

    priv_key = X25519PrivateKey.from_private_bytes(priv_key_data)
    rem_pub_key = priv_key.public_key()
    rem_pub_key_data = rem_pub_key.public_bytes(Encoding.Raw,
                                                PublicFormat.Raw)

    pub_key_data = box_data[:X25519_KEY_SIZE]

    # Get XSalsa20-Poly1305 nonce
    h = hashlib.blake2b(digest_size=XSALSA20POLY1305_NONCE_SIZE)
    h.update(pub_key_data)
    h.update(rem_pub_key_data)
    nonce = h.digest()

    # Get XSalsa20-Poly1305 key
    pub_key = X25519PublicKey.from_public_bytes(pub_key_data)
    shared_secret = priv_key.exchange(pub_key)
    key = salsa.hsalsa(shared_secret, HSALSA_NONCE)

    # XSalsa20-Poly1305 decrypt
    mac_tag = box_data[X25519_KEY_SIZE :
                       X25519_KEY_SIZE + XSALSA20POLY1305_TAG_SIZE]
    enc_data = box_data[X25519_KEY_SIZE + XSALSA20POLY1305_TAG_SIZE:]
    cipher = salsa.Salsa(salsa.Salsa.init_state(key, nonce))
    # !!! Crutch: XSalsa20 -> XSalsa20-Poly1305 :-)
    cipher.decrypt(32 * b'\0')
    data = cipher.decrypt(enc_data)

    return data


if __name__ == '__main__':
    #
    # Main
    #
    import sys
    import io

    if len(sys.argv) != 2:
        print('Usage:', os.path.basename(sys.argv[0]), 'filename')
        sys.exit(0)

    filename = sys.argv[1]

    with io.open('./privkey.bin', 'rb') as f:
        priv_key_data = f.read(X25519_KEY_SIZE)

    with io.open(filename, 'rb') as f:
        box_data = f.read()

    # Decrypt box data
    data = curve25519xsalsa20poly1305_decrypt(box_data, priv_key_data)
    if not data:
        print('Error: Failed to decrypt crypto box')
        sys.exit(1)

    new_filename = filename + '.dec'
    with io.open(new_filename, 'wb') as f:
        f.write(data)
