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

import sys
import io
import os
import struct
import shutil
import c77l


RANSOM_EXT = '.3AE00608'

RANSOM_EXT_PREFIX = '.['
RANSOM_EXT_POSTFIX = ']'


ENC_MARKER = c77l.ENC_MARKER1


def decrypt_file(filename: str, session_keys: dict) -> bool:
    """
    Decrypt file.
    EncryptedByC77L
    LockedByX77C
    EncryptRansomware
    ABBCCDDEEFF0 v1
    """

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        header_size = len(ENC_MARKER) + 1 + 8

        if file_size < header_size:
            return False

        # Read header
        header = f.read(header_size)

        # Check marker
        marker = header[:len(ENC_MARKER)]
        if marker != ENC_MARKER:
            return False

        # Encryption mode
        enc_mode = header[len(ENC_MARKER)]
        print('encryption mode:', enc_mode)

        if enc_mode == 0:
            chunk_info_size = 24
        elif enc_mode == 1:
            chunk_info_size = 8
        else:
            return False

        # Encrypted session key
        enc_skey_size, = struct.unpack_from('<Q', header,
                                            len(ENC_MARKER) + 1)
        enc_session_key = f.read(enc_skey_size)
        print('encrypted session key size:', enc_skey_size)

        # Read chunk info
        chunk_info = f.read(chunk_info_size)

        metadata_size = header_size + enc_skey_size + chunk_info_size
        print('metadata size:', metadata_size)

        # Get session key
        session_key = session_keys.get(enc_session_key)
        if not session_key:
            return False
        session_key = session_key[:c77l.KEY_SIZE]

        print('session key: OK')

        if enc_mode == 1:

            # Full
            enc_size, = struct.unpack_from('<Q', chunk_info, 0)
            print('encrypted data size: %08X' % enc_size)

            if metadata_size + enc_size > file_size:
                return False

            # Read encrypted data
            enc_data = f.read()

            # AES CBC decrypt data
            data = c77l.aes_cbc_decrypt(enc_data, session_key)

            f.seek(0)
            f.write(data)

        else:

            # Spot
            enc_chunk2_size, chunk1_size, enc_size = \
                struct.unpack_from('<3Q', chunk_info, 0)
            print('chunk 1 size: %08X' % chunk1_size)
            print('encrypted chunk 2 size: %08X' % enc_chunk2_size)
            print('encrypted data size: %08X' % enc_size)

            if ((chunk1_size < metadata_size) or
                (enc_size % c77l.AES_BLOCK_SIZE != 0) or
                (metadata_size + enc_size > file_size)):
                return False

            enc_chunk1_size = chunk1_size - metadata_size
            if enc_chunk1_size > enc_size:
                return False

            # Read chunk 1 encrypted data
            enc_chunk1_data = f.read(enc_chunk1_size)

            # Read chunk 2 encrypted data
            f.seek(file_size - enc_chunk2_size)
            enc_chunk2_data = f.read(enc_size - enc_chunk1_size)

            enc_data = enc_chunk1_data + enc_chunk2_data

            # AES CBC decrypt data
            data = c77l.aes_cbc_decrypt(enc_data, session_key)

            # Write chunk 1
            f.seek(0)
            f.write(data[:chunk1_size])

            # Write chunk 2
            f.seek(file_size - enc_chunk2_size)
            f.write(data[chunk1_size:])

        # Remove unnecessary data
        f.truncate()

        return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Check if file is encrypted
if not c77l.is_file_encrypted(filename, ENC_MARKER):
    print('Error: File not encrypted or damaged')
    sys.exit(1)

# Load session keys
session_keys = c77l.load_session_keys('./DecryptionKeys1.bin')
if len(session_keys) == 0:
    print('Error: No session keys loaded')
    sys.exit(1)

new_filename = None

# Get original file name
if filename.endswith(RANSOM_EXT_POSTFIX + RANSOM_EXT):
    pos = filename.rfind(RANSOM_EXT_PREFIX)
    if pos >= 0:
        new_filename = filename[:pos]

if not new_filename:
    new_filename = filename + '.dec'

# Copy file
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, session_keys):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
