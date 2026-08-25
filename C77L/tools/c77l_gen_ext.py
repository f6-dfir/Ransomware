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
from typing import Callable


RANSOM_EXT_CHARS1 = 'abcdefghijklmnopqrstuvwxyz0123456789'
RANSOM_EXT_CHARS2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
RANSOM_EXT_CHARS3 = 'abcdefghijklmnopqrstuvwxyz'


# Hash function type
HashFunc = Callable[[bytes], int]


def fnv1a32(data: bytes) -> int:
    """Compute FNV1A 32 hash"""

    h = 0x811C9DC5
    for b in data:
        h = ((b ^ h) * 0x1000193) & 0xFFFFFFFF
    return h


def fnv1a64(data: bytes) -> int:
    """Compute FNV1A 64 hash"""

    h = 0xCBF29CE484222325
    for b in data:
        h = ((b ^ h) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def get_ransom_ext1(victim_id: str,
                    ext_len: int,
                    hash_func: HashFunc,
                    char_set: str,
                    divider: int = 0) -> str:
    """Get ransom extension"""

    if divider == 0: divider = len(char_set)
    ext = ''
    h = hash_func(victim_id.encode('UTF-16-LE'))
    for i in range(ext_len):
        ext += char_set[h % len(char_set)]
        h //= divider
    return ext


def get_ransom_ext2(victim_id: str,
                    ext_len: int,
                    hash_func: HashFunc,
                    char_set: str) -> str:
    """Get ransom extension"""

    ext = ''
    h = hash_func(victim_id.encode('UTF-16-LE'))
    chars = char_set
    for i in range(ext_len):
        r = h % len(chars)
        ext += chars[r]
        chars = chars[:r] + chars[r + 1:]
        h //= len(chars)
    return ext


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'vol_c_sn')
    sys.exit(0)

vol_c_sn = int(sys.argv[1], 16)
victim_id = '%08X' % vol_c_sn
print('victim ID:', victim_id)

print('ransom extensions:')
ext = '.' + victim_id
print('C77L: \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 5, fnv1a32, RANSOM_EXT_CHARS1)
print('X77C (x86): \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 5, fnv1a64, RANSOM_EXT_CHARS1)
print('X77C (x64): \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 3, fnv1a32, RANSOM_EXT_CHARS1)
print('X77C/EncryptRansomware (x86): \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 3, fnv1a64, RANSOM_EXT_CHARS1)
print('X77C/EncryptRansomware (x64): \"%s\"' % ext)
ext = '.' + get_ransom_ext2(victim_id, 8, fnv1a32, RANSOM_EXT_CHARS2)
print('ABBCCDDEEFF0 (x86): \"%s\"' % ext)
ext = '.' + get_ransom_ext2(victim_id, 8, fnv1a64, RANSOM_EXT_CHARS2)
print('ABBCCDDEEFF0 (x64): \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 8, fnv1a32, RANSOM_EXT_CHARS2)
print('ABBCCDDEEFF0 (x86): \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 8, fnv1a64, RANSOM_EXT_CHARS2)
print('ABBCCDDEEFF0 (x64): \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 8, fnv1a32, RANSOM_EXT_CHARS2, 27)
print('ABBCCDDEEFF0 (x86): \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 8, fnv1a64, RANSOM_EXT_CHARS2, 27)
print('ABBCCDDEEFF0 (x64): \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 5, fnv1a32, RANSOM_EXT_CHARS2, 27)
print('ABBCCDDEEFF0 (x86): \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 5, fnv1a64, RANSOM_EXT_CHARS2, 27)
print('ABBCCDDEEFF0 (x64): \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 5, fnv1a32, RANSOM_EXT_CHARS3)
print('ABBCCDDEEFF0 (x86): \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 5, fnv1a64, RANSOM_EXT_CHARS3)
print('ABBCCDDEEFF0 (x64): \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 3, fnv1a32, RANSOM_EXT_CHARS3)
print('ABBCCDDEEFF0 (x86): \"%s\"' % ext)
ext = '.' + get_ransom_ext1(victim_id, 3, fnv1a64, RANSOM_EXT_CHARS3)
print('ABBCCDDEEFF0 (x64): \"%s\"' % ext)
