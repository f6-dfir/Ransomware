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
import os
import io
import binascii
import c77l


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Read master private RSA key
with io.open('./rsa_privkey.bin', 'rb') as f:
    master_priv_key_data = f.read()

# Read encrypted session key lines
with io.open(filename, 'rt') as f:
    enc_skey_lines = f.read().splitlines()

session_keys = {}

# Decrypt session keys
for i, enc_skey in enumerate(enc_skey_lines):

    # Decrypt session key
    enc_key_data = binascii.unhexlify(enc_skey)
    key_data = c77l.decrypt_session_key1(enc_key_data, master_priv_key_data)
    if not key_data:
        print('Error: Failed to decrypt session key %d' % i)
        continue
    session_keys[enc_key_data] = key_data

print('%d session key(s) decrypted' % len(session_keys))

# Save session keys
c77l.save_session_keys(filename + '.keys', session_keys)
