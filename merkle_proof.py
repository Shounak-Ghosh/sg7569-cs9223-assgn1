"""
Merkle proof verification utilities.
"""

import hashlib
import binascii
import base64

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    """Merkle tree hasher implementing RFC 6962 hashing."""

    def __init__(self, hash_func=hashlib.sha256):
        self.hash_func = hash_func

    def new(self):
        """Create a new hash object."""
        return self.hash_func()

    def empty_root(self):
        """Return the hash of an empty root."""
        return self.new().digest()

    def hash_leaf(self, leaf):
        """Hash a leaf node according to RFC 6962."""
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()

    def hash_children(self, left, right):
        """Hash two child nodes according to RFC 6962."""
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + left + right
        h.update(b)
        return h.digest()

    def size(self):
        """Return the digest size of the hash function."""
        return self.new().digest_size


# DefaultHasher is a SHA256 based LogHasher
DefaultHasher = Hasher(hashlib.sha256)


def verify_consistency(hasher, size1, size2, proof, root1, root2):
    """Verify the consistency of two Merkle tree roots.

    Args:
        hasher (Hasher): The Merkle tree hasher implementing RFC 6962.
        size1 (int): The size of the first tree.
        size2 (int): The size of the second tree.
        proof (list): The consistency proof as a list of hex strings.
        root1 (str): The root hash of the first tree as a hex string.
        root2 (str): The root hash of the second tree as a hex string.

    Raises:
        ValueError: If size2 is less than size1.
        ValueError: If size1 equals size2 but proof is not empty.
        ValueError: If size1 is 0 but proof is not empty.
        ValueError: If proof is empty when it should not be.
        ValueError: If proof size does not match expected size.
        RootMismatchError: If calculated root does not match expected root.
    """
    # change format of args to be bytearray instead of hex strings
    root1 = bytes.fromhex(root1)
    root2 = bytes.fromhex(root2)
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    if size2 < size1:
        raise ValueError(f"size2 ({size2}) < size1 ({size1})")
    if size1 == size2:
        if bytearray_proof:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(root1, root2)
        return
    if size1 == 0:
        if bytearray_proof:
            raise ValueError(
                f"expected empty bytearray_proof, but got {len(bytearray_proof)} components"
            )
        return
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")

    inner, border = decomp_incl_proof(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1
    inner -= shift

    if size1 == 1 << shift:
        seed, start = root1, 0
    else:
        seed, start = bytearray_proof[0], 1

    if len(bytearray_proof) != start + inner + border:
        raise ValueError(
            f"wrong bytearray_proof size {len(bytearray_proof)}, want {start + inner + border}"
        )

    bytearray_proof = bytearray_proof[start:]

    mask = (size1 - 1) >> shift
    hash1 = chain_inner_right(hasher, seed, bytearray_proof[:inner], mask)
    hash1 = chain_border_right(hasher, hash1, bytearray_proof[inner:])
    verify_match(hash1, root1)

    hash2 = chain_inner(hasher, seed, bytearray_proof[:inner], mask)
    hash2 = chain_border_right(hasher, hash2, bytearray_proof[inner:])
    verify_match(hash2, root2)


def verify_match(calculated, expected):
    """Verify that two hash values match.

    Args:
        calculated (bytes): The calculated hash value.
        expected (bytes): The expected hash value.
    Raises:
        RootMismatchError: If calculated hash does not match expected hash.
    """
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index, size):
    """Decompose inclusion proof into inner and border components.

    Args:
        index (int): The index of the leaf.
        size (int): The size of the tree.
    Returns:
        tuple: A tuple containing the inner and border components.
    """
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index, size):
    """Calculate the size of the inner proof.

    Args:
        index (int): The index of the leaf.
        size (int): The size of the tree.

    Returns:
        int: The size of the inner proof.
    """
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher, seed, proof, index):
    """Chain inner nodes of the Merkle proof.

    Args:
        hasher (Hasher): The Merkle tree hasher implementing RFC 6962.
        seed (bytes): The current seed hash.
        proof (list): The list of proof hashes.
        index (int): The index of the leaf.

    Returns:
        bytes: The resulting hash after chaining inner nodes.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_inner_right(hasher, seed, proof, index):
    """Chain inner nodes of the Merkle proof (right side).

    Args:
        hasher (Hasher): The Merkle tree hasher implementing RFC 6962.
        seed (bytes): The current seed hash.
        proof (list): The list of proof hashes.
        index (int): The index of the leaf.

    Returns:
        bytes: The resulting hash after chaining inner nodes.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_border_right(hasher, seed, proof):
    """Chain border nodes of the Merkle proof (right side).

    Args:
        hasher (Hasher): The Merkle tree hasher implementing RFC 6962.
        seed (bytes): The current seed hash.
        proof (list): The list of proof hashes.

    Returns:
        bytes: The resulting hash after chaining border nodes.
    """
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed


class RootMismatchError(Exception):
    """Exception raised when calculated root does not match expected root."""

    def __init__(self, expected_root, calculated_root):
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self):
        return (
            f"calculated root:\n{self.calculated_root}\n "
            f"does not match expected root:\n{self.expected_root}"
        )


def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
    """Calculate the Merkle tree root from an inclusion proof.

    Args:
        hasher (Hasher): The Merkle tree hasher implementing RFC 6962.
        index (int): The index of the leaf in the tree.
        size (int): The size of the tree.
        leaf_hash (bytes): The hash of the leaf.
        proof (list): The Merkle inclusion proof as a list of byte arrays.

    Returns:
        bytes: The calculated root hash.

    Raises:
        ValueError: If index is beyond tree size.
        ValueError: If leaf_hash size does not match hasher size.
        ValueError: If proof size does not match expected size.
    """
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(
            f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}"
        )

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(hasher, index, size, leaf_hash, proof, root, debug=False):
    """Verify the inclusion of a leaf in a Merkle tree.

    Args:
        hasher (Hasher): The Merkle tree hasher implementing RFC 6962.
        index (int): The index of the leaf.
        size (int): The size of the tree.
        leaf_hash (str): The hash of the leaf as a hex string.
        proof (list): The Merkle proof as a list of hex strings.
        root (str): The root hash of the Merkle tree as a hex string.
        debug (bool, optional): Whether to print debug information. Defaults to False.

    Raises:
        ValueError: If index is beyond tree size.
        ValueError: If leaf_hash size does not match hasher size.
        ValueError: If proof size does not match expected size.
        RootMismatchError: If calculated root does not match expected root.
    """
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    bytearray_root = bytes.fromhex(root)
    bytearray_leaf = bytes.fromhex(leaf_hash)
    calc_root = root_from_inclusion_proof(
        hasher, index, size, bytearray_leaf, bytearray_proof
    )
    verify_match(calc_root, bytearray_root)
    if debug:
        print("Calculated root hash", calc_root.hex())
        print("Given root hash", bytearray_root.hex())


# requires entry["body"] output for a log entry
# returns the leaf hash according to the rfc 6962 spec
def compute_leaf_hash(body):
    """Compute the leaf hash according to RFC 6962.

    Args:
        body (str): The base64-encoded body of the log entry.

    Returns:
        str: The computed leaf hash as a hexadecimal string.
    """
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    h = hashlib.sha256()
    # write the leaf hash prefix
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    h.update(entry_bytes)

    # return the computed hash
    return h.hexdigest()
