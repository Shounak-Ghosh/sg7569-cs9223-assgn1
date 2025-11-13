"""Tests for util module."""

import base64
import json
import datetime
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

from assignment1.util import (
    extract_public_key,
    verify_artifact_signature,
    verify_artifact_with_log_entry,
)


class TestExtractPublicKey:
    """Tests for extract_public_key function."""

    def test_extract_public_key_valid_cert(self, tmp_path):
        """Test extracting public key from a valid certificate."""
        # Generate a test certificate
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Test Org"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=1)
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        # Extract public key
        public_key_pem = extract_public_key(cert_pem)

        # Verify it's a valid PEM public key
        assert b"-----BEGIN PUBLIC KEY-----" in public_key_pem
        assert b"-----END PUBLIC KEY-----" in public_key_pem

    def test_extract_public_key_invalid_cert(self):
        """Test extracting public key from invalid certificate data."""
        invalid_cert = b"not a valid certificate"
        with pytest.raises(Exception):
            extract_public_key(invalid_cert)


class TestVerifyArtifactSignature:
    """Tests for verify_artifact_signature function."""

    def test_verify_artifact_signature_valid(self, tmp_path):
        """Test verification with valid signature."""
        # Create a test artifact
        artifact_path = tmp_path / "test_artifact.txt"
        artifact_path.write_bytes(b"test data")

        # Generate key pair and sign
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        signature = private_key.sign(b"test data", ec.ECDSA(hashes.SHA256()))

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Should not raise any exception
        verify_artifact_signature(signature, public_key_pem, str(artifact_path))

    def test_verify_artifact_signature_invalid_signature(self, tmp_path):
        """Test verification with invalid signature."""
        artifact_path = tmp_path / "test_artifact.txt"
        artifact_path.write_bytes(b"test data")

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        # Wrong signature
        signature = b"invalid signature data"

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with pytest.raises((InvalidSignature, ValueError)):
            verify_artifact_signature(signature, public_key_pem, str(artifact_path))

    def test_verify_artifact_signature_file_not_found(self):
        """Test verification when artifact file doesn't exist."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        signature = b"some signature"

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with pytest.raises(FileNotFoundError):
            verify_artifact_signature(signature, public_key_pem, "/nonexistent/file.txt")


class TestVerifyArtifactWithLogEntry:
    """Tests for verify_artifact_with_log_entry function."""

    def test_verify_artifact_with_log_entry_missing_body(self):
        """Test with log entry missing body field."""
        log_entry = {}
        with pytest.raises(ValueError, match="does not contain 'body' field"):
            verify_artifact_with_log_entry(log_entry, "artifact.txt")

    def test_verify_artifact_with_log_entry_missing_spec(self):
        """Test with log entry missing spec field."""
        body = base64.b64encode(json.dumps({}).encode()).decode()
        log_entry = {"body": body}
        with pytest.raises(ValueError, match="Missing 'spec' field"):
            verify_artifact_with_log_entry(log_entry, "artifact.txt")

    def test_verify_artifact_with_log_entry_missing_signature(self):
        """Test with log entry missing signature field."""
        body_data = {"spec": {}}
        body = base64.b64encode(json.dumps(body_data).encode()).decode()
        log_entry = {"body": body}
        with pytest.raises(ValueError, match="Missing 'signature' field"):
            verify_artifact_with_log_entry(log_entry, "artifact.txt")

    def test_verify_artifact_with_log_entry_missing_public_key(self):
        """Test with log entry missing publicKey field."""
        body_data = {"spec": {"signature": {}}}
        body = base64.b64encode(json.dumps(body_data).encode()).decode()
        log_entry = {"body": body}
        with pytest.raises(ValueError, match="Missing 'publicKey' field"):
            verify_artifact_with_log_entry(log_entry, "artifact.txt")

    def test_verify_artifact_with_log_entry_missing_public_key_content(self):
        """Test with log entry missing publicKey content."""
        body_data = {"spec": {"signature": {"publicKey": {}}}}
        body = base64.b64encode(json.dumps(body_data).encode()).decode()
        log_entry = {"body": body}
        with pytest.raises(ValueError, match="Missing 'content' field in publicKey"):
            verify_artifact_with_log_entry(log_entry, "artifact.txt")

    def test_verify_artifact_with_log_entry_missing_signature_content(self):
        """Test with log entry missing signature content."""
        body_data = {"spec": {"signature": {"publicKey": {"content": "test"}}}}
        body = base64.b64encode(json.dumps(body_data).encode()).decode()
        log_entry = {"body": body}
        with pytest.raises(ValueError, match="Missing 'content' field in signature"):
            verify_artifact_with_log_entry(log_entry, "artifact.txt")
