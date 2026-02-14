"""
Rekor Transparency Log Verifier

A tool for verifying artifact inclusion and consistency in the Rekor transparency log
using Merkle proofs and cryptographic verification.
"""

__version__ = "0.1.0"

from assignment1.merkle_proof import (
    DEFAULT_HASHER,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
    ConsistencyProof,
    InclusionProof,
)
from assignment1.util import verify_artifact_with_log_entry
from assignment1.main import (
    get_log_entry,
    get_verification_proof,
    inclusion,
    consistency,
    get_latest_checkpoint,
    main,
)

__all__ = [
    "DEFAULT_HASHER",
    "verify_consistency",
    "verify_inclusion",
    "compute_leaf_hash",
    "ConsistencyProof",
    "InclusionProof",
    "verify_artifact_with_log_entry",
    "get_log_entry",
    "get_verification_proof",
    "inclusion",
    "consistency",
    "get_latest_checkpoint",
    "main",
    "__version__",
]
