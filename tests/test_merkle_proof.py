"""Tests for merkle_proof module."""

import hashlib
import pytest
from assignment1.merkle_proof import (
    Hasher,
    DefaultHasher,
    ConsistencyProof,
    InclusionProof,
    RootMismatchError,
    verify_consistency,
    verify_inclusion,
    verify_match,
    compute_leaf_hash,
    decomp_incl_proof,
    inner_proof_size,
    chain_inner,
    chain_inner_right,
    chain_border_right,
    root_from_inclusion_proof,
    RFC6962_LEAF_HASH_PREFIX,
    RFC6962_NODE_HASH_PREFIX,
)


class TestHasher:
    """Tests for the Hasher class."""

    def test_hasher_initialization(self):
        """Test that Hasher initializes correctly."""
        hasher = Hasher(hashlib.sha256)
        assert hasher.hash_func == hashlib.sha256

    def test_hasher_new(self):
        """Test that new() creates a hash object."""
        hasher = Hasher(hashlib.sha256)
        h = hasher.new()
        assert h is not None
        assert hasattr(h, 'update')
        assert hasattr(h, 'digest')

    def test_hasher_empty_root(self):
        """Test empty_root returns correct hash."""
        hasher = Hasher(hashlib.sha256)
        empty = hasher.empty_root()
        expected = hashlib.sha256().digest()
        assert empty == expected

    def test_hasher_size(self):
        """Test size returns correct digest size."""
        hasher = Hasher(hashlib.sha256)
        assert hasher.size() == 32

    def test_hasher_hash_leaf(self):
        """Test hash_leaf with RFC 6962 prefix."""
        hasher = Hasher(hashlib.sha256)
        leaf_data = b"test data"
        result = hasher.hash_leaf(leaf_data)

        # Manually compute expected hash
        expected_hash = hashlib.sha256()
        expected_hash.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        expected_hash.update(leaf_data)
        expected = expected_hash.digest()

        assert result == expected

    def test_hasher_hash_children(self):
        """Test hash_children with RFC 6962 prefix."""
        hasher = Hasher(hashlib.sha256)
        left = b"left_hash"
        right = b"right_hash"
        result = hasher.hash_children(left, right)

        # Manually compute expected hash
        expected_hash = hashlib.sha256()
        expected_hash.update(bytes([RFC6962_NODE_HASH_PREFIX]) + left + right)
        expected = expected_hash.digest()

        assert result == expected


class TestComputeLeafHash:
    """Tests for compute_leaf_hash function."""

    def test_compute_leaf_hash_valid_input(self):
        """Test compute_leaf_hash with valid base64 input."""
        import base64
        test_data = b"Hello, World!"
        encoded = base64.b64encode(test_data).decode('utf-8')

        result = compute_leaf_hash(encoded)

        # Manually compute expected hash
        expected_hash = hashlib.sha256()
        expected_hash.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        expected_hash.update(test_data)
        expected = expected_hash.hexdigest()

        assert result == expected

    def test_compute_leaf_hash_empty_data(self):
        """Test compute_leaf_hash with empty data."""
        import base64
        encoded = base64.b64encode(b"").decode('utf-8')
        result = compute_leaf_hash(encoded)
        assert isinstance(result, str)
        assert len(result) == 64


class TestRootMismatchError:
    """Tests for RootMismatchError exception."""

    def test_root_mismatch_error_message(self):
        """Test that RootMismatchError formats message correctly."""
        expected = b"expected_hash"
        calculated = b"calculated_hash"
        error = RootMismatchError(expected, calculated)

        error_str = str(error)
        assert "calculated root" in error_str
        assert "expected root" in error_str

    def test_root_mismatch_error_attributes(self):
        """Test RootMismatchError stores hash values correctly."""
        expected = b"expected"
        calculated = b"calculated"
        error = RootMismatchError(expected, calculated)

        assert error.expected_root is not None
        assert error.calculated_root is not None


class TestVerifyMatch:
    """Tests for verify_match function."""

    def test_verify_match_identical_hashes(self):
        """Test verify_match with identical hashes."""
        hash1 = b"identical_hash"
        hash2 = b"identical_hash"
        verify_match(hash1, hash2)

    def test_verify_match_different_hashes(self):
        """Test verify_match with different hashes raises RootMismatchError."""
        hash1 = b"hash_one"
        hash2 = b"hash_two"
        with pytest.raises(RootMismatchError):
            verify_match(hash1, hash2)


class TestRootFromInclusionProof:
    """Tests for root_from_inclusion_proof function."""

    def test_root_from_inclusion_proof_index_beyond_size(self):
        """Test that index >= size raises ValueError."""
        hasher = DefaultHasher
        index = 10
        size = 5
        leaf_hash = b"a" * 32
        proof = []

        with pytest.raises(ValueError, match="index is beyond size"):
            root_from_inclusion_proof(hasher, index, size, leaf_hash, proof)

    def test_root_from_inclusion_proof_invalid_leaf_size(self):
        """Test that invalid leaf_hash size raises ValueError."""
        hasher = DefaultHasher
        index = 0
        size = 1
        leaf_hash = b"invalid_size"
        proof = []

        with pytest.raises(ValueError, match="leaf_hash has unexpected size"):
            root_from_inclusion_proof(hasher, index, size, leaf_hash, proof)


class TestVerifyInclusion:
    """Tests for verify_inclusion function."""

    def test_verify_inclusion_invalid_index(self):
        """Test verify_inclusion with index beyond size."""
        hasher = DefaultHasher
        index = 10
        size = 5
        inclusion_proof = InclusionProof(
            leaf_hash="a" * 64,
            proof=[],
            root="b" * 64
        )

        with pytest.raises(ValueError, match="index is beyond size"):
            verify_inclusion(hasher, index, size, inclusion_proof)


class TestVerifyConsistency:
    """Tests for verify_consistency function."""

    def test_verify_consistency_size2_less_than_size1(self):
        """Test that size2 < size1 raises ValueError."""
        hasher = DefaultHasher
        size1 = 10
        size2 = 5
        consistency_proof = ConsistencyProof(
            proof=[],
            root1="a" * 64,
            root2="b" * 64
        )

        with pytest.raises(ValueError, match="size2.*<.*size1"):
            verify_consistency(hasher, size1, size2, consistency_proof)

    def test_verify_consistency_equal_sizes_empty_proof(self):
        """Test consistency when sizes are equal with empty proof."""
        hasher = DefaultHasher
        size1 = 5
        size2 = 5
        root = "a" * 64
        consistency_proof = ConsistencyProof(
            proof=[],
            root1=root,
            root2=root
        )

        verify_consistency(hasher, size1, size2, consistency_proof)

    def test_verify_consistency_equal_sizes_non_empty_proof(self):
        """Test consistency when sizes are equal but proof is not empty."""
        hasher = DefaultHasher
        size1 = 5
        size2 = 5
        consistency_proof = ConsistencyProof(
            proof=["a" * 64],
            root1="a" * 64,
            root2="a" * 64
        )

        with pytest.raises(ValueError, match="size1=size2.*not empty"):
            verify_consistency(hasher, size1, size2, consistency_proof)

    def test_verify_consistency_size1_zero_empty_proof(self):
        """Test consistency when size1=0 with empty proof."""
        hasher = DefaultHasher
        size1 = 0
        size2 = 5
        consistency_proof = ConsistencyProof(
            proof=[],
            root1="a" * 64,
            root2="b" * 64
        )

        verify_consistency(hasher, size1, size2, consistency_proof)

    def test_verify_consistency_size1_zero_non_empty_proof(self):
        """Test consistency when size1=0 but proof is not empty."""
        hasher = DefaultHasher
        size1 = 0
        size2 = 5
        consistency_proof = ConsistencyProof(
            proof=["a" * 64],
            root1="a" * 64,
            root2="b" * 64
        )

        with pytest.raises(ValueError, match="expected empty.*proof"):
            verify_consistency(hasher, size1, size2, consistency_proof)

    def test_verify_consistency_empty_proof_when_needed(self):
        """Test consistency when proof is needed but empty."""
        hasher = DefaultHasher
        size1 = 5
        size2 = 10
        consistency_proof = ConsistencyProof(
            proof=[],
            root1="a" * 64,
            root2="b" * 64
        )

        with pytest.raises(ValueError, match="empty.*proof"):
            verify_consistency(hasher, size1, size2, consistency_proof)


class TestChainFunctions:
    """Tests for chain_inner, chain_inner_right, and chain_border_right functions."""

    def test_chain_inner_basic(self):
        """Test chain_inner with basic inputs."""
        hasher = DefaultHasher
        seed = b"a" * 32
        proof = [b"b" * 32, b"c" * 32]
        index = 1

        result = chain_inner(hasher, seed, proof, index)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_chain_inner_empty_proof(self):
        """Test chain_inner with empty proof."""
        hasher = DefaultHasher
        seed = b"a" * 32
        proof = []
        index = 0

        result = chain_inner(hasher, seed, proof, index)
        assert result == seed

    def test_chain_inner_right_basic(self):
        """Test chain_inner_right with basic inputs."""
        hasher = DefaultHasher
        seed = b"a" * 32
        proof = [b"b" * 32, b"c" * 32]
        index = 3

        result = chain_inner_right(hasher, seed, proof, index)
        assert isinstance(result, bytes)

    def test_chain_border_right_basic(self):
        """Test chain_border_right with basic inputs."""
        hasher = DefaultHasher
        seed = b"a" * 32
        proof = [b"b" * 32, b"c" * 32]

        result = chain_border_right(hasher, seed, proof)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_chain_border_right_empty_proof(self):
        """Test chain_border_right with empty proof."""
        hasher = DefaultHasher
        seed = b"a" * 32
        proof = []

        result = chain_border_right(hasher, seed, proof)
        assert result == seed


class TestDecompInclProof:
    """Tests for decomp_incl_proof function."""

    def test_decomp_incl_proof_basic(self):
        """Test decomp_incl_proof with basic values."""
        index = 5
        size = 8
        inner, border = decomp_incl_proof(index, size)
        assert isinstance(inner, int)
        assert isinstance(border, int)

    def test_decomp_incl_proof_edge_case(self):
        """Test decomp_incl_proof with edge case values."""
        index = 0
        size = 1
        inner, border = decomp_incl_proof(index, size)
        assert isinstance(inner, int)
        assert isinstance(border, int)


class TestInnerProofSize:
    """Tests for inner_proof_size function."""

    def test_inner_proof_size_basic(self):
        """Test inner_proof_size with basic values."""
        index = 5
        size = 8
        result = inner_proof_size(index, size)
        assert isinstance(result, int)
        assert result >= 0

    def test_inner_proof_size_zero_index(self):
        """Test inner_proof_size with zero index."""
        index = 0
        size = 4
        result = inner_proof_size(index, size)
        assert isinstance(result, int)
