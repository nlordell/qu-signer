"""
@title eXtended Merkle Signature Scheme
@license GPL-3.0-only
@author Nicholas Rodrigues Lordello <n@lordello.net>
@notice Module implementing `XMSS-SHA2_*_256` from RFC-8391
@dev
    This module implements the SHA-256 constructions of the XMSS signature
	scheme (without multi-trees).
"""


### Hash Function Addresses
# The following section contains definitions related to the hash function
# address schemed used for hash function randomization in XMSS.

_TYPE_OTS: constant(uint32) = 0
_TYPE_LTREE: constant(uint32) = 1
_TYPE_HTREE: constant(uint32) = 2

@internal
@pure
def _set_field(_adrs: bytes32, _offset: uint256, _val: uint32) -> bytes32:
    mask: uint256 = convert(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000, uint256) << _offset
    hi: uint256 = convert(_adrs, uint256) & mask
    lo: uint256 = convert(_val, uint256) << _offset
    return convert(hi | lo, bytes32)

@internal
@pure
def _set_type(_adrs: bytes32, _type: uint32) -> bytes32:
    return self._set_field(_adrs, 128, _type)

@internal
@pure
def _set_ots_address(_adrs: bytes32, _ots_address: uint32) -> bytes32:
    return self._set_field(_adrs, 96, _ots_address)

@internal
@pure
def _set_ltree_address(_adrs: bytes32, _ltree_address: uint32) -> bytes32:
    return self._set_field(_adrs, 96, _ltree_address)

@internal
@pure
def _set_chain_address(_adrs: bytes32, _chain_address: uint32) -> bytes32:
    return self._set_field(_adrs, 64, _chain_address)

@internal
@pure
def _set_tree_height(_adrs: bytes32, _tree_height: uint32) -> bytes32:
    return self._set_field(_adrs, 64, _tree_height)

@internal
@pure
def _set_hash_address(_adrs: bytes32, _hash_address: uint32) -> bytes32:
    return self._set_field(_adrs, 32, _hash_address)

@internal
@pure
def _set_tree_index(_adrs: bytes32, _tree_index: uint32) -> bytes32:
    return self._set_field(_adrs, 32, _tree_index)

@internal
@pure
def _set_key_and_mask(_adrs: bytes32, _key_and_mask: uint32) -> bytes32:
    return self._set_field(_adrs, 0, _key_and_mask)


### Keyed Hash Functions
# Keyed hash functions used by XMSS.

@internal
@pure
def _f(_key: bytes32, _m: bytes32) -> bytes32:
    buffer: Bytes[96] = concat(convert(0, bytes32), _key, _m)
    return sha256(buffer)

@internal
@pure
def _h(_key: bytes32, _m: Bytes[64]) -> bytes32:
    buffer: Bytes[128] = concat(convert(1, bytes32), _key, _m)
    return sha256(buffer)

@internal
@pure
def _h_msg(_key: Bytes[96], _m: bytes32) -> bytes32:
    buffer: Bytes[160] = concat(convert(2, bytes32), _key, _m)
    return sha256(buffer)

@internal
@pure
def _prf(_key: bytes32, _m: bytes32) -> bytes32:
    buffer: Bytes[96] = concat(convert(3, bytes32), _key, _m)
    return sha256(buffer)

@internal
@pure
def _prf_keygen(_key: bytes32, _m: Bytes[64]) -> bytes32:
    buffer: Bytes[128] = concat(convert(4, bytes32), _key, _m)
    return sha256(buffer)


### Base-16
# Base-16 encoding of a string.

@internal
@pure
def _base_16_char(_m: bytes32, _csum: uint256, _i: uint32) -> (uint32, uint256):
    m: uint256 = convert(_m, uint256)
    c: uint256 = 0
    if _i < 64:
        offset: uint256 = unsafe_sub(63, convert(_i, uint256)) << 2
        c = (m >> offset) & 15
        _csum = unsafe_add(_csum, unsafe_sub(15, c))
    else:
        offset: uint256 = unsafe_sub(66, convert(_i, uint256)) << 2
        c = (_csum >> offset) & 15
    return convert(c, uint32), _csum

@internal
@pure
def _base_16_char_branchless(_m: bytes32, _csum: uint256, _i: uint32) -> (uint32, uint256):
    m: uint256 = convert(_m, uint256)
    offset: uint256 = unsafe_sub(63, convert(_i, uint256)) << 2
    c: uint256 = ((m >> offset) | (_csum >> unsafe_add(offset, 12))) & 15
    csum: uint256 = unsafe_mul(convert(_i < 64, uint256), unsafe_sub(15, c))
    return convert(c, uint32), unsafe_add(_csum, csum)


### WOTS+
# The following section contains definitions related to the Winternitz One-Time
# Signature Plus signing primitive. We only require support for WOTSP-SHA2_256
# which has the following parameters:
#
#     +----------+----+----+-----+
#     | F / PRF  |  n |  w | len |
#     +----------+----+----+-----+
#     | SHA2-256 | 32 | 16 |  67 |
#     +----------+----+----+-----+

@internal
@pure
def _chain(_k: bytes32, _i: uint32, _s: uint32, _seed: bytes32, _adrs: bytes32) -> bytes32:
    result: bytes32 = _k
    key: bytes32 = empty(bytes32)
    bm: bytes32 = empty(bytes32)
    for j: uint32 in range(_s, bound=15):
        _adrs = self._set_hash_address(_adrs, unsafe_add(_i, j))
        key = self._prf(_seed, _adrs)
        _adrs = self._set_key_and_mask(_adrs, 1)
        bm = self._prf(_seed, _adrs)
        result = self._f(key, self._xor(bm, result))
    return result

@internal
@pure
def _pubkey(_sk: bytes32, _seed: bytes32, _adrs: bytes32) -> bytes32[67]:
    pk: bytes32[67] = empty(bytes32[67])
    k: bytes32 = empty(bytes32)
    for i: uint32 in range(67):
        _adrs = self._set_chain_address(_adrs, i)
        k = self._prf_keygen(_sk, concat(_seed, _adrs))
        pk[i] = self._chain(k, 0, 15, _seed, _adrs)
    return pk

@internal
@pure
def _sign(_sk: bytes32, _m: bytes32, _seed: bytes32, _adrs: bytes32) -> bytes32[67]:
    sig: bytes32[67] = empty(bytes32[67])
    k: bytes32 = empty(bytes32)
    c: uint32 = 0
    csum: uint256 = 0
    for i: uint32 in range(67):
        _adrs = self._set_chain_address(_adrs, i)
        k = self._prf_keygen(_sk, concat(_seed, _adrs))
        c, csum = self._base_16_char(_m, csum, i)
        sig[i] = self._chain(k, 0, c, _seed, _adrs)
    return sig

@internal
@pure
def _recover(_m: bytes32, _sig: bytes32[67], _seed: bytes32, _adrs: bytes32) -> bytes32[67]:
    c: uint32 = 0
    csum: uint256 = 0
    s: uint32 = 0
    for i: uint32 in range(67):
        _adrs = self._set_chain_address(_adrs, i)
        c, csum = self._base_16_char(_m, csum, i)
        s = unsafe_sub(15, c)
        _sig[i] = self._chain(_sig[i], c, s, _seed, _adrs)
    return _sig


### XMSS
# The following section contains definitions related to the eXtended Merkle
# Signature Scheme. We implement the following parameters:
#
#     +-------------------+-----------+----+----+-----+----+
#     | Name              | Functions |  n |  w | len |  h |
#     +-------------------+-----------+----+----+-----+----+
#     | XMSS-SHA2_10_256  | SHA2-256  | 32 | 16 |  67 | 10 |
#     | XMSS-SHA2_16_256  | SHA2-256  | 32 | 16 |  67 | 16 |
#     | XMSS-SHA2_20_256  | SHA2-256  | 32 | 16 |  67 | 20 |
#     +-------------------+-----------+----+----+-----+----+

@internal
@pure
def _rand_hash(_left: bytes32, _right: bytes32, _seed: bytes32, _adrs: bytes32) -> bytes32:
    key: bytes32 = self._prf(_seed, self._set_key_and_mask(_adrs, 0))
    bm0: bytes32 = self._prf(_seed, self._set_key_and_mask(_adrs, 1))
    bm1: bytes32 = self._prf(_seed, self._set_key_and_mask(_adrs, 2))
    m: Bytes[64] = concat(self._xor(bm0, _left), self._xor(bm1, _right))
    return self._h(key, m)

@internal
@pure
def _ltree(_pk: bytes32[67], _seed: bytes32, _adrs: bytes32) -> bytes32:
    l: uint256 = 67
    j: uint256 = 0
    left: bytes32 = empty(bytes32)
    right: bytes32 = empty(bytes32)
    for height: uint32 in range(7):
        _adrs = self._set_tree_height(_adrs, height)
        for i: uint256 in range(l >> 1, bound=33):
            j = i << 1
            left = _pk[j]
            right = _pk[unsafe_add(j, 1)]
            _adrs = self._set_tree_index(_adrs, convert(i, uint32))
            _pk[i] = self._rand_hash(left, right, _seed, _adrs)
        if l & 1 != 0:
            _pk[l >> 1] = _pk[unsafe_sub(l, 1)]
        l = unsafe_add(l, 1) >> 1
    return _pk[0]


### Utilities
# Some ungrouped utilities. Lets hope the compiler inlines these...

@internal
@pure
def _char(_m: Bytes[67], _i: uint32) -> uint32:
    return convert(slice(_m, convert(_i, uint256), 1), uint32)

@internal
@pure
def _xor(_a: bytes32, _b: bytes32) -> bytes32:
    return convert(convert(_a, uint256) ^ convert(_b, uint256), bytes32)


### TESTING
# TODO: remove me...

@external
@pure
def my_test_func() -> uint256:
    sk: bytes32 = sha256("secret")
    m: bytes32 = sha256("Hello, WOTS+!")
    seed: bytes32 = sha256("seed")
    adrs: bytes32 = convert(42 << 160, bytes32)
    sig: bytes32[67] = self._sign(sk, m, seed, adrs)
    pk: bytes32[67] = self._recover(m, sig, seed, adrs)
    adrs = self._set_type(adrs, _TYPE_LTREE)
    leaf: bytes32 = self._ltree(pk, seed, adrs)
    return convert(leaf, uint256)
