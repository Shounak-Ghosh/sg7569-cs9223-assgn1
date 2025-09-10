import argparse
import json
import requests
import base64
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    # verify that log index value is sane
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log_index must be a non-negative integer")

    REKOR_API_URL = "https://rekor.sigstore.dev/api/v1/log/entries"
    params = {"logIndex": log_index}
    try:
        response = requests.get(REKOR_API_URL, params=params)
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
        # Return the full JSON response (dict of UUID: entry)
        uuid = next(iter(data))
        entry = data[uuid]
        return entry
    except Exception as e:
        if debug:
            print(f"Error fetching log entry: {e}")
        return None

def get_verification_proof(log_index, debug=False):
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
    decoded_body = base64.b64decode(body_b64).decode('utf-8')
    if debug:
        print("Decoded body:", decoded_body)
    body_json = json.loads(decoded_body)
    signature_json = body_json.get("spec", {}).get("signature", {})
    public_key_cert = signature_json.get("publicKey", {}).get("content")
    signature_b64 = signature_json.get("content")
    if debug:
        print("Public Key Certificate (base64):", public_key_cert)
        print("Signature (base64):", signature_b64)

    # Ensure public_key_cert is properly decoded and formatted as a PEM file
    try:
        if isinstance(public_key_cert, str):
            public_key_cert = base64.b64decode(public_key_cert)
        if not public_key_cert.startswith(b"-----BEGIN CERTIFICATE-----"):
            public_key_cert = b"-----BEGIN CERTIFICATE-----\n" + public_key_cert + b"\n-----END CERTIFICATE-----"
    except Exception as e:
        raise ValueError("Failed to decode or format public key certificate") from e

    public_key = extract_public_key(public_key_cert)
    signature = base64.b64decode(signature_b64)
    if debug:
        print("Extracted Public Key (PEM):", public_key.decode('utf-8'))
        print("Decoded Signature (bytes):", signature)

    if verify_artifact_signature(signature, public_key, "artifact.md"):
        print("Artifact signature successfully verified.")
    
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

    if verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash, debug):
        print("Inclusion proof successfully verified.")

def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane
    # extract_public_key(certificate)
    # verify_artifact_signature(signature, public_key, artifact_filepath)
    # get_verification_proof(log_index)
    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    pass

def get_latest_checkpoint(debug=False):
    pass

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    # get_latest_checkpoint()
    pass

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    # main()

    # print(get_log_entry(495027577, debug=True))
    print(get_verification_proof(495027577, debug=True))