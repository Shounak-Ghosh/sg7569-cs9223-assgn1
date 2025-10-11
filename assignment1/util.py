"""
Utility functions for cryptographic operations.
"""

import base64
import json

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature


def extract_public_key(cert):
    """Extract and return public key from a given certificate in PEM format.

    Args:
        cert (bytes): The certificate in PEM format.

    Returns:
        bytes: The public key in PEM format.
    """
    # read the certificate
    #    with open("cert.pem", "rb") as cert_file:
    #        cert_data = cert_file.read()

    # load the certificate
    certificate = x509.load_pem_x509_certificate(cert, default_backend())

    # extract the public key
    public_key = certificate.public_key()

    # save the public key to a PEM file
    #    with open("cert_public.pem", "wb") as pub_key_file:
    #        pub_key_file.write(public_key.public_bytes(
    #            encoding=serialization.Encoding.PEM,
    #            format=serialization.PublicFormat.SubjectPublicKeyInfo
    #        ))
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return pem_public_key


def verify_artifact_signature(signature, public_key, artifact_filename):
    """Verify the signature of an artifact using the provided public key.

    Args:
        signature (bytes): The signature to verify.
        public_key (bytes): The public key in PEM format.
        artifact_filename (str): The path to the artifact file.

    Raises:
        InvalidSignature: If the signature is invalid.
        ValueError: If there's an error in the verification process.
        TypeError: If there's a type error in the verification process.
        FileNotFoundError: If the artifact file is not found.
    """
    # load the public key
    # with open("cert_public.pem", "rb") as pub_key_file:
    #    public_key = load_pem_public_key(pub_key_file.read())

    # load the signature
    #    with open("hello.sig", "rb") as sig_file:
    #        signature = sig_file.read()

    public_key = load_pem_public_key(public_key)
    # load the data to be verified
    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    # verify the signature
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise InvalidSignature(
            "Signature verification failed: signature is invalid"
        ) from e
    except (ValueError, TypeError) as e:
        raise ValueError(f"Signature verification failed: {e}") from e


def verify_artifact_with_log_entry(log_entry, artifact_filepath, debug=False):
    """Helper function to verify artifact signature using log entry data.

    Args:
        log_entry (dict): The log entry containing signature information.
        artifact_filepath (str): The file path of the artifact to verify.
        debug (bool, optional): If True, print debug information. Defaults to False.

    Raises:
        ValueError: If log entry is missing required fields or schema validation fails.
        KeyError: If expected fields are missing from the Rekor log entry schema.
        Exception: If signature verification fails.
    """
    body_b64 = log_entry.get("body")
    if not body_b64:
        raise ValueError("Log entry does not contain 'body' field")

    decoded_body = base64.b64decode(body_b64).decode("utf-8")
    if debug:
        print("Decoded body:\n", decoded_body)

    body_json = json.loads(decoded_body)

    # Fail fast if the expected schema is not present
    try:
        if "spec" not in body_json:
            raise KeyError("Missing 'spec' field in log entry body")
        if "signature" not in body_json["spec"]:
            raise KeyError("Missing 'signature' field in log entry spec")

        signature_json = body_json["spec"]["signature"]

        if "publicKey" not in signature_json:
            raise KeyError("Missing 'publicKey' field in signature")
        if "content" not in signature_json["publicKey"]:
            raise KeyError("Missing 'content' field in publicKey")
        if "content" not in signature_json:
            raise KeyError("Missing 'content' field in signature")

        public_key_cert = signature_json["publicKey"]["content"]
        signature_b64 = signature_json["content"]
    except KeyError as e:
        raise ValueError(f"Rekor log entry schema validation failed: {e}") from e

    # Decode the public key certificate if it's base64 encoded
    try:
        if isinstance(public_key_cert, str):
            public_key_cert = base64.b64decode(public_key_cert)
    except Exception as e:
        raise ValueError("Failed to decode public key certificate from base64") from e

    # Extract public key - this will validate the certificate format
    public_key = extract_public_key(public_key_cert)
    signature = base64.b64decode(signature_b64)

    if debug:
        print("Extracted Public Key (PEM):", public_key.decode("utf-8"))
        print("Decoded Signature (bytes):", signature)

    verify_artifact_signature(signature, public_key, artifact_filepath)
