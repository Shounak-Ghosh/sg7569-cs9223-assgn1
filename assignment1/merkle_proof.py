"""
Merkle proof verification utilities.
"""

import hashlib
import binascii
import base64
from dataclasses import dataclass

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


@dataclass
class ConsistencyProof:
    """Container for consistency proof data."""

    proof: list
    root1: str
    root2: str


@dataclass
class InclusionProof:
    """Container for inclusion proof data."""

    leaf_hash: str
    proof: list
    root: str


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
DEFAULT_HASHER = Hasher(hashlib.sha256)


def _validate_consistency_inputs(size1, size2, proof_len, root1, root2):
    """Validate consistency proof inputs.

    Args:
        size1 (int): The size of the first tree.
        size2 (int): The size of the second tree.
        proof_len (int): The length of the proof.
        root1 (bytes): The first root hash.
        root2 (bytes): The second root hash.

    Raises:
        ValueError: If inputs are invalid.
    """
    if size2 < size1:
        raise ValueError(f"size2 ({size2}) < size1 ({size1})")
    if size1 == size2:
        if proof_len > 0:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(root1, root2)
        return True
    if size1 == 0:
        if proof_len > 0:
            raise ValueError(f"expected empty bytearray_proof, but got {proof_len} components")
        return True
    if proof_len == 0:
        raise ValueError("empty bytearray_proof")
    return False


def verify_consistency(hasher, size1, size2, consistency_proof):
    """Verify the consistency of two Merkle tree roots.

    Args:
        hasher (Hasher): The Merkle tree hasher implementing RFC 6962.
        size1 (int): The size of the first tree.
        size2 (int): The size of the second tree.
        consistency_proof (ConsistencyProof): The consistency proof data.

    Raises:
        ValueError: If size2 is less than size1.
        ValueError: If size1 equals size2 but proof is not empty.
        ValueError: If size1 is 0 but proof is not empty.
        ValueError: If proof is empty when it should not be.
        ValueError: If proof size does not match expected size.
        RootMismatchError: If calculated root does not match expected root.
    """
    # change format of args to be bytearray instead of hex strings
    root1_bytes = bytes.fromhex(consistency_proof.root1)
    root2_bytes = bytes.fromhex(consistency_proof.root2)
    bytearray_proof = [bytes.fromhex(elem) for elem in consistency_proof.proof]

    # Validate inputs and handle edge cases
    if _validate_consistency_inputs(size1, size2, len(bytearray_proof), root1_bytes, root2_bytes):
        return

    inner, border = decomp_incl_proof(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1
    inner -= shift

    seed, start = (root1_bytes, 0) if size1 == 1 << shift else (bytearray_proof[0], 1)

    if len(bytearray_proof) != start + inner + border:
        raise ValueError(f"wrong bytearray_proof size {len(bytearray_proof)}, want {start + inner + border}")

    proof_slice = bytearray_proof[start:]
    mask = (size1 - 1) >> shift

    # Verify first hash path
    verify_match(
        chain_border_right(
            hasher,
            chain_inner_right(hasher, seed, proof_slice[:inner], mask),
            proof_slice[inner:],
        ),
        root1_bytes,
    )

    # Verify second hash path
    verify_match(
        chain_border_right(
            hasher,
            chain_inner(hasher, seed, proof_slice[:inner], mask),
            proof_slice[inner:],
        ),
        root2_bytes,
    )


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
        return f"calculated root:\n{self.calculated_root}\n does not match expected root:\n{self.expected_root}"


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
        raise ValueError(f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}")

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(hasher, index, size, inclusion_proof, debug=False):
    """Verify the inclusion of a leaf in a Merkle tree.

    Args:
        hasher (Hasher): The Merkle tree hasher implementing RFC 6962.
        index (int): The index of the leaf.
        size (int): The size of the tree.
        inclusion_proof (InclusionProof): The inclusion proof data.
        debug (bool, optional): Whether to print debug information. Defaults to False.

    Raises:
        ValueError: If index is beyond tree size.
        ValueError: If leaf_hash size does not match hasher size.
        ValueError: If proof size does not match expected size.
        RootMismatchError: If calculated root does not match expected root.
    """
    bytearray_proof = [bytes.fromhex(elem) for elem in inclusion_proof.proof]
    bytearray_root = bytes.fromhex(inclusion_proof.root)
    bytearray_leaf = bytes.fromhex(inclusion_proof.leaf_hash)

    calc_root = root_from_inclusion_proof(hasher, index, size, bytearray_leaf, bytearray_proof)
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
