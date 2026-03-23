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
import hashlib
import genie


RANSOM_EXT = '.0000000000000000'


# Footer
ENC_MARKER = b'GENIELOCK'
FOOTER_HEADER_SIZE = 4 + 4 + len(ENC_MARKER)

# Metadata
METADATA_PERCENT_POS = 1
METADATA_NONCE_POS = METADATA_PERCENT_POS + 1
METADATA_NONCE_SIZE = genie.XCHACHA20_NONCE_SIZE
METADATA_FILESIZE_POS = METADATA_NONCE_POS + METADATA_NONCE_SIZE
METADATA_SIZEINBLOCKS_POS = METADATA_FILESIZE_POS + 8
METADATA_BLOCKSIZE_POS = METADATA_SIZEINBLOCKS_POS + 8
METADATA_LASTBLOCKSIZE_POS = METADATA_BLOCKSIZE_POS + 4
METADATA_DATADIGEST_POS = METADATA_LASTBLOCKSIZE_POS + 4
METADATA_DATADIGEST_SIZE = 32
METADATA_NUMBLOCKS_POS = METADATA_DATADIGEST_POS + METADATA_DATADIGEST_SIZE
METADATA_RANSOMEXT_POS = METADATA_NUMBLOCKS_POS + 4
METADATA_RANSOMEXT_SIZE = 64
METADATA_TAG_POS = METADATA_RANSOMEXT_POS + METADATA_RANSOMEXT_SIZE
METADATA_TAG_SIZE = genie.XCHACHA20POLY1305_TAG_SIZE


ENC_BLOCK_SIZE = 0x1000000


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < FOOTER_HEADER_SIZE:
            return False

        # Read footer header
        f.seek(-FOOTER_HEADER_SIZE, 2)
        footer_hdr = f.read(FOOTER_HEADER_SIZE)

        # Check encryption marker
        marker = footer_hdr[8:]
        if marker != ENC_MARKER:
            return False

        enc_metadata_size, footer_size = struct.unpack_from('<LL',
                                                            footer_hdr, 0)

        print('enc metadata size:', enc_metadata_size)
        print('footer size:', footer_size)

        if footer_size <= FOOTER_HEADER_SIZE:
            return False

        footer_data_size = footer_size - FOOTER_HEADER_SIZE
        if (footer_data_size <= enc_metadata_size +
                                genie.XCHACHA20_NONCE_SIZE):
            return False

        if file_size < footer_size:
            return False

        # Read footer data
        f.seek(-footer_size, 2)
        footer_data = f.read(footer_data_size)

        enc_keydata_size = (footer_data_size -
                            (enc_metadata_size + genie.XCHACHA20_NONCE_SIZE))

        enc_keydata = footer_data[:enc_keydata_size]
        nonce = footer_data[enc_keydata_size: 
                            enc_keydata_size + genie.XCHACHA20_NONCE_SIZE]
        enc_metadata = footer_data[enc_keydata_size +
                                   genie.XCHACHA20_NONCE_SIZE:
                                   footer_data_size]

        # Decrypt XChaCha20-Poly1305 key
        key = genie.curve25519xsalsa20poly1305_decrypt(enc_keydata,
                                                       priv_key_data)
        if not key:
            return False

        # Decrypt metadata (XChaCha20-Poly1305)
        metadata = genie.xchacha20poly1305_decrypt2(enc_metadata, key, nonce)
        if not metadata:
            return False

        print('metadata size:', len(metadata))

        if len(metadata) < METADATA_TAG_POS:
            return False

        # Parse metadata
        if metadata[0] != 1:
            return False

        enc_percent = metadata[METADATA_PERCENT_POS]
        nonce2 = metadata[METADATA_NONCE_POS:
                          METADATA_NONCE_POS + METADATA_NONCE_SIZE]
        orig_file_size, size_in_blocks, block_size, last_block_size = \
            struct.unpack_from('<QQLL', metadata, METADATA_FILESIZE_POS)
        data_digest = metadata[METADATA_DATADIGEST_POS:
                               METADATA_DATADIGEST_POS +
                               METADATA_DATADIGEST_SIZE]
        num_blocks, = struct.unpack_from('<L', metadata,
                                         METADATA_NUMBLOCKS_POS)
        ransom_ext_data = metadata[METADATA_RANSOMEXT_POS:
                                   METADATA_RANSOMEXT_POS +
                                   METADATA_RANSOMEXT_SIZE]
        ransom_ext = ransom_ext_data.rstrip(b'\0').decode()

        enc_size = num_blocks * block_size

        mask_pos = METADATA_TAG_POS + num_blocks * METADATA_TAG_SIZE
        mask_size = (size_in_blocks + 7) >> 3
        metadata_size = mask_pos + mask_size

        print('ransom ext:', ransom_ext)
        print('encryption percent: %d%%' % enc_percent)
        print('original size:', orig_file_size)
        print('size in blocks:', size_in_blocks)
        print('block size:', block_size)
        print('last block size:', last_block_size)
        print('blocks:', num_blocks)

        if len(metadata) < metadata_size:
            return False

        # Decrypt file data
        h = hashlib.blake2b(digest_size=METADATA_DATADIGEST_SIZE)

        i = 0
        block_index = 0

        while (i < size_in_blocks) and (block_index < num_blocks):

            mask_byte_index, mask_bit_index = divmod(i, 8)
            mask = metadata[mask_pos + mask_byte_index]
            if mask & (1 << mask_bit_index) == 0:
                i += 1
                continue

            pos = i * block_size
            tag = metadata[METADATA_TAG_POS +
                           block_index * METADATA_TAG_SIZE:
                           METADATA_TAG_POS +
                           (block_index + 1) * METADATA_TAG_SIZE]

            # Read block
            f.seek(pos)
            size = block_size if i != size_in_blocks - 1 else last_block_size
            enc_data = f.read(size)

            # Update XChaCha20-Poly1305 nonce
            n = bytearray(nonce2)
            for j in range(8):
                n[j] ^= (i >> (j * 8)) & 0xFF

            # Decrypt block (XChaCha20-Poly1305)
            data = genie.xchacha20poly1305_decrypt(enc_data, key, n, tag)
            if not data:
                print(i)
                return False

            # Update data hash
            h.update(data)

            # Write block
            f.seek(pos)
            f.write(data)

            i += 1
            block_index += 1

        # Check decrypted data hash
        d = h.digest()
        if d != data_digest:
            return False

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
