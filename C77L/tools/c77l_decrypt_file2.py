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


ENC_MARKER = c77l.ENC_MARKER4


def decrypt_file(decrypt_func: c77l.DecryptFunc,
                 filename: str,
                 session_keys: dict) -> bool:
    """
    Decrypt file.
    ABBCCDDEEFF0 v2
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
            chunk_info_size = 32
        elif enc_mode == 1:
            chunk_info_size = 8
        else:
            return False

        # Encrypted session key
        enc_skey_size, = struct.unpack_from('<Q', header,
                                            len(ENC_MARKER) + 1)
        enc_session_key = f.read(enc_skey_size)
        print('encrypted session key size:', enc_skey_size)

        # Encrypted original file name
        enc_filename_size = int.from_bytes(f.read(8), 'little')
        enc_filename = f.read(enc_filename_size)

        # Chunk info
        chunk_info = f.read(chunk_info_size)

        metadata_size = (header_size + enc_skey_size +
                         8 + enc_filename_size +
                         chunk_info_size)
        print('metadata size:', metadata_size)

        # Get session key
        session_key = session_keys.get(enc_session_key)
        if not session_key:
            return False
        session_key = session_key[:c77l.KEY_SIZE]

        print('session key: OK')

        # Decrypt original file name
        dec_filename = decrypt_func(enc_filename, session_key)
        if (len(dec_filename) == 0) or (len(dec_filename) & 1 != 0):
            return False
        orig_filename = dec_filename.decode('UTF-16LE')
        print('original file name: \"%s\"' % orig_filename)

        if enc_mode == 1:

            # Full
            enc_size, = struct.unpack_from('<Q', chunk_info, 0)
            print('encrypted data size: %08X' % enc_size)

            if metadata_size + enc_size > file_size:
                return False

            # Read encrypted data
            enc_data = f.read()

            # Decrypt data
            data = decrypt_func(enc_data, session_key)

            f.seek(0)
            f.write(data)

            # Remove unnecessary data
            f.truncate()

        else:

            # Spot
            enc_chunk2_size, chunk1_size, enc_size, orig_file_size = \
                struct.unpack_from('<4Q', chunk_info, 0)
            print('chunk 1 size: %08X' % chunk1_size)
            print('encrypted chunk 2 size: %08X' % enc_chunk2_size)
            print('encrypted data size: %08X' % enc_size)
            print('original file size:', orig_file_size)

            if ((chunk1_size < metadata_size) or
                (metadata_size + orig_file_size > file_size) or
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

            # Decrypt data
            data = decrypt_func(enc_data, session_key)

            # Write chunk 1
            f.seek(0)
            f.write(data[:chunk1_size])

            # Write chunk 2
            f.seek(file_size - enc_chunk2_size)
            f.write(data[chunk1_size:])

            # Remove unnecessary data
            f.truncate(orig_file_size)

    # Restore original file name
    dest_filename = os.path.join(os.path.abspath(os.path.dirname(filename)),
                                 orig_filename)
    if os.path.isfile(dest_filename):
        os.remove(dest_filename)
    os.rename(filename, dest_filename)

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
session_keys = c77l.load_session_keys('./DecryptionKeys2.bin')
if len(session_keys) == 0:
    print('Error: No session keys loaded')
    sys.exit(1)

new_filename = filename + '.dec'

# Copy file
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(c77l.aes_ctr_decrypt, new_filename, session_keys):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
