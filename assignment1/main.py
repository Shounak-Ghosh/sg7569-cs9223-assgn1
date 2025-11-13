"""
Rekor Transparency Log Verifier

This module provides command-line tools to verify artifact inclusion and consistency
in the Rekor transparency log using Merkle proofs.
"""

import argparse
import json
import os
import requests
from assignment1.util import verify_artifact_with_log_entry
from assignment1.merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
    ConsistencyProof,
    InclusionProof,
)

# Constants
REKOR_LOGS_URL = "https://rekor.sigstore.dev/api/v1/log"
REKOR_ENTRIES_URL = "https://rekor.sigstore.dev/api/v1/log/entries"
REKOR_PROOF_URL = "https://rekor.sigstore.dev/api/v1/log/proof"


def get_log_entry(log_index, debug=False):
    """Fetch a log entry from the Rekor transparency log.

    Args:
        log_index (int): The index of the log entry to fetch.
        debug (bool, optional): If True, print debug information. Defaults to False.
    Raises:
        ValueError: If the log_index is not a non-negative integer.

    Returns:
        dict: The log entry data if found, else None.
    """
    # verify that log index value is sane
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log_index must be a non-negative integer")

    params = {"logIndex": log_index}
    try:
        response = requests.get(REKOR_ENTRIES_URL, params=params, timeout=10)
        if debug:
            print(f"Request URL: {response.url}")
            print(f"Status Code: {response.status_code}")
        response.raise_for_status()
        data = response.json()
        if debug:
            print(json.dumps(data, indent=2))
        # The API returns a dict with UUID as key
        if not data:
            if debug:
                print("No entry found for the given log index.")
            return None
        # Return the entry from response (dict of UUID: entry)
        uuid = next(iter(data))
        entry = data[uuid]
        return entry
    except requests.RequestException as e:
        if debug:
            print(f"Error fetching log entry: {e}")
        return None


def get_verification_proof(log_index, debug=False):
    """Fetch the verification proof for a given log index.

    Args:
        log_index (int): The index of the log entry to fetch the proof for.
        debug (bool, optional): If True, print debug information. Defaults to False.
    Raises:
        ValueError: If the log_index is not a non-negative integer.
        ValueError: If no log entry is found for the given log index.
        ValueError: If the log entry does not contain 'body' field.
        ValueError: If the log entry does not contain 'inclusionProof' field.

    Returns:
        tuple: A tuple containing index, tree_size, leaf_hash, hashes, and root_hash.
    """
    # verify that log index value is sane
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log_index must be a non-negative integer")
    log_entry = get_log_entry(log_index, debug)
    if log_entry is None:
        raise ValueError("No log entry found for the given log index")
    # Extract signature and certificate from log_entry (encoded in base64)
    # Start by decoding the body to get the full entry
    body_b64 = log_entry.get("body")
    if not body_b64:
        raise ValueError("Log entry does not contain 'body' field")

    leaf_hash = compute_leaf_hash(body_b64)
    if debug:
        print("Computed Leaf Hash:", leaf_hash)

    inclusion_proof_json = log_entry.get("verification", {}).get("inclusionProof", {})
    if not inclusion_proof_json:
        raise ValueError("Log entry does not contain 'inclusionProof' field")

    index = inclusion_proof_json.get("logIndex")
    tree_size = inclusion_proof_json.get("treeSize")
    hashes = inclusion_proof_json.get("hashes", [])
    root_hash = inclusion_proof_json.get("rootHash")

    return index, tree_size, leaf_hash, hashes, root_hash


def inclusion(log_index, artifact_filepath, debug=False):
    """Verify inclusion of an artifact in the transparency log.

    Args:
        log_index (int): The index of the log entry.
        artifact_filepath (str): The file path of the artifact to verify.
        debug (bool, optional): If True, print debug information. Defaults to False.

    Raises:
        ValueError: If log_index is not a non-negative integer.
        ValueError: If artifact_filepath is not a non-empty string.
        ValueError: If artifact_filepath is not a valid file.
        FileNotFoundError: If the artifact file does not exist.
        ValueError: If no log entry is found for the given log index.
        ValueError: If the log entry does not contain 'body' field.
        ValueError: If the log entry does not contain 'verification' field.
        ValueError: If inclusion verification fails.
    """
    # verify that log index and artifact filepath values are sane
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log_index must be a non-negative integer")
    if not isinstance(artifact_filepath, str) or not artifact_filepath:
        raise ValueError("artifact_filepath must be a non-empty string")

    # Check if the artifact file exists
    if not os.path.exists(artifact_filepath):
        raise FileNotFoundError(f"Artifact file not found: {artifact_filepath}")

    # Check if it's actually a file (not a directory)
    if not os.path.isfile(artifact_filepath):
        raise ValueError(f"Artifact path is not a file: {artifact_filepath}")

    log_entry = get_log_entry(log_index, debug)
    if log_entry is None:
        raise ValueError("No log entry found for the given log index")

    try:
        # Verify artifact signature
        verify_artifact_with_log_entry(log_entry, artifact_filepath, debug)
        print("Signature is valid.")

        # Verify inclusion proof
        index, tree_size, leaf_hash, hashes, root_hash = get_verification_proof(
            log_index, debug
        )
        inclusion_proof = InclusionProof(
            leaf_hash=leaf_hash, proof=hashes, root=root_hash
        )
        verify_inclusion(DefaultHasher, index, tree_size, inclusion_proof)
        print("Offline root hash calculation for inclusion verified.")
    except Exception as e:
        raise ValueError(f"Inclusion verification failed: {e}") from e


def get_latest_checkpoint(debug=False):
    """Fetch the latest checkpoint from the Rekor transparency log.

    Args:
        debug (bool, optional): If True, print debug information. Defaults to False.

    Returns:
        dict: The latest checkpoint data if fetched successfully, else None.
    """
    # fetch the latest checkpoint from the Rekor server
    try:
        response = requests.get(REKOR_LOGS_URL, timeout=10)
        if debug:
            print(f"Request URL: {response.url}")
            print(f"Status Code: {response.status_code}")
        response.raise_for_status()
        data = response.json()
        if debug:
            print(json.dumps(data, indent=2))
        return data
    except requests.RequestException as e:
        if debug:
            print(f"Error fetching latest checkpoint: {e}")
        return None


def consistency(prev_checkpoint, debug=False):
    """Verify consistency of a given checkpoint with the latest checkpoint.

    Args:
        prev_checkpoint (dict): The previous checkpoint data.
        debug (bool, optional): If True, print debug information. Defaults to False.

    Raises:
        ValueError: If failed to fetch consistency proof from Rekor API.
        Exception: Exception raised during consistency verification.
    """
    # verify that prev checkpoint is not empty
    if not prev_checkpoint:
        print("Previous checkpoint is empty")
        return
    latest_checkpoint = get_latest_checkpoint(debug)
    if not latest_checkpoint:
        print("Failed to fetch latest checkpoint")
        return
    latest_tree_size = latest_checkpoint.get("treeSize")
    # get consistency proof
    proof = None
    try:
        params = {
            "firstSize": prev_checkpoint.get("treeSize"),
            "lastSize": latest_tree_size,
            "treeID": prev_checkpoint.get("treeID"),
        }
        response = requests.get(REKOR_PROOF_URL, params=params, timeout=10)
        if debug:
            print(f"Request URL: {response.url}")
            print(f"Status Code: {response.status_code}")
        response.raise_for_status()
        data = response.json()
        proof = data.get("hashes", [])
        if debug:
            print(json.dumps(data, indent=2))
    except requests.RequestException as e:
        error_msg = f"Failed to fetch consistency proof: {e}"
        if debug:
            print(error_msg)
        raise ValueError(error_msg) from e

    # compare prev_checkpoint with latest_checkpoint
    try:
        consistency_proof = ConsistencyProof(
            proof=proof,
            root1=prev_checkpoint.get("rootHash"),
            root2=latest_checkpoint.get("rootHash"),
        )
        verify_consistency(
            DefaultHasher,
            prev_checkpoint.get("treeSize"),
            latest_tree_size,
            consistency_proof,
        )
        print("Consistency verification successful.")
    except Exception as e:
        raise ValueError(f"Consistency verification failed: {e}") from e


def handle_checkpoint(debug):
    """Fetch and print the latest checkpoint from the Rekor server."""
    checkpoint = get_latest_checkpoint(debug)
    print(json.dumps(checkpoint, indent=4))


def handle_inclusion(args, debug):
    """Verify inclusion of an artifact in the transparency log."""
    if not args.artifact:
        print("Error: --artifact is required for inclusion verification")
        return
    inclusion(args.inclusion, args.artifact, debug)


def handle_consistency(args, debug):
    """Verify consistency of a given checkpoint with the latest checkpoint."""
    missing = []
    if not args.tree_id:
        missing.append("tree id")
    if not args.tree_size:
        missing.append("tree size")
    if not args.root_hash:
        missing.append("root hash")
    if missing:
        print(f"please specify {' and '.join(missing)} for prev checkpoint")
        return
    prev_checkpoint = {
        "treeID": args.tree_id,
        "treeSize": args.tree_size,
        "rootHash": args.root_hash,
    }
    consistency(prev_checkpoint, debug)


def main():
    """
    Main function to parse arguments and execute Rekor verification commands.
    """

    def get_args():
        parser = argparse.ArgumentParser(description="Rekor Verifier")
        parser.add_argument(
            "-d", "--debug", help="Debug mode", required=False, action="store_true"
        )  # Default false
        parser.add_argument(
            "-c",
            "--checkpoint",
            help="Obtain latest checkpoint from Rekor Server public instance",
            required=False,
            action="store_true",
        )
        parser.add_argument(
            "--inclusion",
            help=(
                "Verify inclusion of an entry in the Rekor Transparency Log using log index "
                "and artifact filename. "
                "Usage: --inclusion 126574567"
            ),
            required=False,
            type=int,
        )
        parser.add_argument(
            "--artifact",
            help="Artifact filepath for verifying signature",
            required=False,
        )
        parser.add_argument(
            "--consistency",
            help="Verify consistency of a given checkpoint with the latest checkpoint.",
            action="store_true",
        )
        parser.add_argument(
            "--tree-id", help="Tree ID for consistency proof", required=False
        )
        parser.add_argument(
            "--tree-size",
            help="Tree size for consistency proof",
            required=False,
            type=int,
        )
        parser.add_argument(
            "--root-hash", help="Root hash for consistency proof", required=False
        )
        return parser.parse_args()

    def handle_debug(args):
        debug = False
        if args.debug:
            debug = True
            print("enabled debug mode")
        return debug

    args = get_args()
    debug = handle_debug(args)

    def handle_exceptions(func):
        try:
            func()
        except ValueError as e:
            print(f"Error: {e}")
            if debug:
                raise
        except FileNotFoundError as e:
            print(f"Error: {e}")
            if debug:
                raise
        except (TypeError, KeyError, IndexError) as e:
            print(f"Unexpected error: {e}")
            if debug:
                raise

    def run_commands():
        if args.checkpoint:
            handle_checkpoint(debug)
        if args.inclusion:
            handle_inclusion(args, debug)
        if args.consistency:
            handle_consistency(args, debug)

    handle_exceptions(run_commands)


if __name__ == "__main__":
    main()
