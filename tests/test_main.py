"""Tests for main module."""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from assignment1.main import (
    get_log_entry,
    get_verification_proof,
    inclusion,
    get_latest_checkpoint,
    consistency,
    handle_checkpoint,
    handle_inclusion,
    handle_consistency,
)


class TestGetLogEntry:
    """Tests for get_log_entry function."""

    def test_get_log_entry_invalid_log_index_negative(self):
        """Test get_log_entry with negative log index."""
        with pytest.raises(ValueError, match="log_index must be a non-negative integer"):
            get_log_entry(-1)

    def test_get_log_entry_invalid_log_index_non_integer(self):
        """Test get_log_entry with non-integer log index."""
        with pytest.raises(ValueError, match="log_index must be a non-negative integer"):
            get_log_entry("not an integer")

    @patch('assignment1.main.requests.get')
    def test_get_log_entry_success(self, mock_get):
        """Test successful log entry retrieval."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "uuid123": {"body": "test_body", "verification": {}}
        }
        mock_get.return_value = mock_response

        result = get_log_entry(123456)
        assert result is not None
        assert "body" in result

    @patch('assignment1.main.requests.get')
    def test_get_log_entry_with_debug(self, mock_get, capsys):
        """Test log entry retrieval with debug mode."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.url = "http://test.com"
        mock_response.json.return_value = {
            "uuid123": {"body": "test_body", "verification": {}}
        }
        mock_get.return_value = mock_response

        result = get_log_entry(123456, debug=True)
        captured = capsys.readouterr()
        assert "Request URL:" in captured.out
        assert "Status Code:" in captured.out

    @patch('assignment1.main.requests.get')
    def test_get_log_entry_empty_response(self, mock_get):
        """Test log entry retrieval with empty response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_get.return_value = mock_response

        result = get_log_entry(123456)
        assert result is None

    @patch('assignment1.main.requests.get')
    def test_get_log_entry_request_exception(self, mock_get):
        """Test log entry retrieval with request exception."""
        import requests
        mock_get.side_effect = requests.RequestException("Network error")

        result = get_log_entry(123456)
        assert result is None


class TestGetVerificationProof:
    """Tests for get_verification_proof function."""

    def test_get_verification_proof_invalid_log_index(self):
        """Test get_verification_proof with invalid log index."""
        with pytest.raises(ValueError, match="log_index must be a non-negative integer"):
            get_verification_proof(-1)

    @patch('assignment1.main.get_log_entry')
    def test_get_verification_proof_no_log_entry(self, mock_get_log):
        """Test get_verification_proof when log entry is not found."""
        mock_get_log.return_value = None

        with pytest.raises(ValueError, match="No log entry found"):
            get_verification_proof(123456)

    @patch('assignment1.main.get_log_entry')
    def test_get_verification_proof_missing_body(self, mock_get_log):
        """Test get_verification_proof with missing body field."""
        mock_get_log.return_value = {"verification": {}}

        with pytest.raises(ValueError, match="does not contain 'body' field"):
            get_verification_proof(123456)

    @patch('assignment1.main.get_log_entry')
    def test_get_verification_proof_missing_inclusion_proof(self, mock_get_log):
        """Test get_verification_proof with missing inclusionProof."""
        import base64
        body = base64.b64encode(b"test data").decode()
        mock_get_log.return_value = {"body": body, "verification": {}}

        with pytest.raises(ValueError, match="does not contain 'inclusionProof' field"):
            get_verification_proof(123456)


class TestInclusion:
    """Tests for inclusion function."""

    def test_inclusion_invalid_log_index(self):
        """Test inclusion with invalid log index."""
        with pytest.raises(ValueError, match="log_index must be a non-negative integer"):
            inclusion(-1, "artifact.txt")

    def test_inclusion_invalid_artifact_filepath(self):
        """Test inclusion with invalid artifact filepath."""
        with pytest.raises(ValueError, match="artifact_filepath must be a non-empty string"):
            inclusion(123456, "")

    def test_inclusion_file_not_found(self):
        """Test inclusion when artifact file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            inclusion(123456, "/nonexistent/file.txt")

    def test_inclusion_directory_instead_of_file(self, tmp_path):
        """Test inclusion when path is a directory."""
        directory = tmp_path / "test_dir"
        directory.mkdir()

        with pytest.raises(ValueError, match="Artifact path is not a file"):
            inclusion(123456, str(directory))


class TestGetLatestCheckpoint:
    """Tests for get_latest_checkpoint function."""

    @patch('assignment1.main.requests.get')
    def test_get_latest_checkpoint_success(self, mock_get):
        """Test successful checkpoint retrieval."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "treeSize": 100,
            "rootHash": "abc123",
            "treeID": "rekor"
        }
        mock_get.return_value = mock_response

        result = get_latest_checkpoint()
        assert result is not None
        assert "treeSize" in result

    @patch('assignment1.main.requests.get')
    def test_get_latest_checkpoint_with_debug(self, mock_get, capsys):
        """Test checkpoint retrieval with debug mode."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.url = "http://test.com"
        mock_response.json.return_value = {
            "treeSize": 100,
            "rootHash": "abc123",
            "treeID": "rekor"
        }
        mock_get.return_value = mock_response

        result = get_latest_checkpoint(debug=True)
        captured = capsys.readouterr()
        assert "Request URL:" in captured.out

    @patch('assignment1.main.requests.get')
    def test_get_latest_checkpoint_request_exception(self, mock_get):
        """Test checkpoint retrieval with request exception."""
        import requests
        mock_get.side_effect = requests.RequestException("Network error")

        result = get_latest_checkpoint()
        assert result is None


class TestConsistency:
    """Tests for consistency function."""

    def test_consistency_empty_prev_checkpoint(self, capsys):
        """Test consistency with empty previous checkpoint."""
        consistency({})
        captured = capsys.readouterr()
        assert "Previous checkpoint is empty" in captured.out

    @patch('assignment1.main.get_latest_checkpoint')
    def test_consistency_failed_to_fetch_latest(self, mock_get_latest, capsys):
        """Test consistency when latest checkpoint fetch fails."""
        mock_get_latest.return_value = None
        prev_checkpoint = {"treeSize": 10, "treeID": "test", "rootHash": "abc"}

        consistency(prev_checkpoint)
        captured = capsys.readouterr()
        assert "Failed to fetch latest checkpoint" in captured.out


class TestHandleCheckpoint:
    """Tests for handle_checkpoint function."""

    @patch('assignment1.main.get_latest_checkpoint')
    def test_handle_checkpoint(self, mock_get_checkpoint, capsys):
        """Test handle_checkpoint function."""
        mock_get_checkpoint.return_value = {"treeSize": 100}

        handle_checkpoint(False)
        captured = capsys.readouterr()
        assert "treeSize" in captured.out


class TestHandleInclusion:
    """Tests for handle_inclusion function."""

    def test_handle_inclusion_missing_artifact(self, capsys):
        """Test handle_inclusion with missing artifact."""
        args = Mock()
        args.inclusion = 123456
        args.artifact = None

        handle_inclusion(args, False)
        captured = capsys.readouterr()
        assert "artifact is required" in captured.out


class TestHandleConsistency:
    """Tests for handle_consistency function."""

    def test_handle_consistency_missing_tree_id(self, capsys):
        """Test handle_consistency with missing tree_id."""
        args = Mock()
        args.tree_id = None
        args.tree_size = 10
        args.root_hash = "abc123"

        handle_consistency(args, False)
        captured = capsys.readouterr()
        assert "tree id" in captured.out

    def test_handle_consistency_missing_tree_size(self, capsys):
        """Test handle_consistency with missing tree_size."""
        args = Mock()
        args.tree_id = "test"
        args.tree_size = None
        args.root_hash = "abc123"

        handle_consistency(args, False)
        captured = capsys.readouterr()
        assert "tree size" in captured.out

    def test_handle_consistency_missing_root_hash(self, capsys):
        """Test handle_consistency with missing root_hash."""
        args = Mock()
        args.tree_id = "test"
        args.tree_size = 10
        args.root_hash = None

        handle_consistency(args, False)
        captured = capsys.readouterr()
        assert "root hash" in captured.out

    @patch('assignment1.main.consistency')
    def test_handle_consistency_all_params_present(self, mock_consistency):
        """Test handle_consistency with all parameters."""
        args = Mock()
        args.tree_id = "test"
        args.tree_size = 10
        args.root_hash = "abc123"

        handle_consistency(args, False)
        mock_consistency.assert_called_once()


class TestConsistencyWithProof:
    """Additional tests for consistency function."""

    @patch('assignment1.main.requests.get')
    @patch('assignment1.main.get_latest_checkpoint')
    def test_consistency_request_exception(self, mock_get_latest, mock_get):
        """Test consistency with request exception during proof fetch."""
        import requests
        mock_get_latest.return_value = {"treeSize": 20, "rootHash": "def456"}
        mock_get.side_effect = requests.RequestException("Network error")

        prev_checkpoint = {"treeSize": 10, "treeID": "test", "rootHash": "abc123"}

        with pytest.raises(ValueError, match="Failed to fetch consistency proof"):
            consistency(prev_checkpoint, False)


class TestInclusionWithMocking:
    """Additional tests for inclusion function with mocking."""

    @patch('assignment1.main.verify_inclusion')
    @patch('assignment1.main.get_verification_proof')
    @patch('assignment1.main.verify_artifact_with_log_entry')
    @patch('assignment1.main.get_log_entry')
    def test_inclusion_verification_failure(self, mock_get_log, mock_verify_artifact,
                                           mock_get_proof, mock_verify_inclusion, tmp_path):
        """Test inclusion when verification fails."""
        artifact = tmp_path / "test.txt"
        artifact.write_text("test")

        mock_get_log.return_value = {"body": "test"}
        mock_verify_artifact.return_value = None
        mock_get_proof.return_value = (0, 1, "leaf", [], "root")
        mock_verify_inclusion.side_effect = Exception("Verification failed")

        with pytest.raises(ValueError, match="Inclusion verification failed"):
            inclusion(0, str(artifact), False)

    @patch('assignment1.main.verify_inclusion')
    @patch('assignment1.main.get_verification_proof')
    @patch('assignment1.main.verify_artifact_with_log_entry')
    @patch('assignment1.main.get_log_entry')
    def test_inclusion_success(self, mock_get_log, mock_verify_artifact,
                              mock_get_proof, mock_verify_inclusion, tmp_path, capsys):
        """Test successful inclusion verification."""
        artifact = tmp_path / "test.txt"
        artifact.write_text("test")

        mock_get_log.return_value = {"body": "test"}
        mock_verify_artifact.return_value = None
        mock_get_proof.return_value = (0, 1, "leaf", [], "root")
        mock_verify_inclusion.return_value = None

        inclusion(0, str(artifact), False)
        captured = capsys.readouterr()
        assert "Signature is valid" in captured.out
        assert "Offline root hash calculation for inclusion verified" in captured.out


class TestConsistencySuccess:
    """Tests for successful consistency verification."""

    @patch('assignment1.main.verify_consistency')
    @patch('assignment1.main.requests.get')
    @patch('assignment1.main.get_latest_checkpoint')
    def test_consistency_success(self, mock_get_latest, mock_get, mock_verify_consistency, capsys):
        """Test successful consistency verification."""
        mock_get_latest.return_value = {
            "treeSize": 20,
            "rootHash": "def456",
            "treeID": "test"
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"hashes": ["hash1", "hash2"]}
        mock_get.return_value = mock_response

        mock_verify_consistency.return_value = None

        prev_checkpoint = {"treeSize": 10, "treeID": "test", "rootHash": "abc123"}

        consistency(prev_checkpoint, False)
        captured = capsys.readouterr()
        assert "Consistency verification successful" in captured.out

    @patch('assignment1.main.verify_consistency')
    @patch('assignment1.main.requests.get')
    @patch('assignment1.main.get_latest_checkpoint')
    def test_consistency_verification_failure(self, mock_get_latest, mock_get, mock_verify_consistency):
        """Test consistency verification failure."""
        mock_get_latest.return_value = {
            "treeSize": 20,
            "rootHash": "def456",
            "treeID": "test"
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"hashes": ["hash1", "hash2"]}
        mock_get.return_value = mock_response

        mock_verify_consistency.side_effect = Exception("Verification failed")

        prev_checkpoint = {"treeSize": 10, "treeID": "test", "rootHash": "abc123"}

        with pytest.raises(ValueError, match="Consistency verification failed"):
            consistency(prev_checkpoint, False)


class TestGetVerificationProofSuccess:
    """Tests for successful get_verification_proof."""

    @patch('assignment1.main.get_log_entry')
    @patch('assignment1.main.compute_leaf_hash')
    def test_get_verification_proof_success(self, mock_compute_hash, mock_get_log):
        """Test successful get_verification_proof."""
        import base64
        body = base64.b64encode(b"test data").decode()

        mock_get_log.return_value = {
            "body": body,
            "verification": {
                "inclusionProof": {
                    "logIndex": 123,
                    "treeSize": 1000,
                    "hashes": ["hash1", "hash2"],
                    "rootHash": "root123"
                }
            }
        }

        mock_compute_hash.return_value = "computed_leaf_hash"

        index, tree_size, leaf_hash, hashes, root_hash = get_verification_proof(123456, False)

        assert index == 123
        assert tree_size == 1000
        assert leaf_hash == "computed_leaf_hash"
        assert hashes == ["hash1", "hash2"]
        assert root_hash == "root123"

    @patch('assignment1.main.get_log_entry')
    @patch('assignment1.main.compute_leaf_hash')
    def test_get_verification_proof_with_debug(self, mock_compute_hash, mock_get_log, capsys):
        """Test get_verification_proof with debug enabled."""
        import base64
        body = base64.b64encode(b"test data").decode()

        mock_get_log.return_value = {
            "body": body,
            "verification": {
                "inclusionProof": {
                    "logIndex": 123,
                    "treeSize": 1000,
                    "hashes": ["hash1", "hash2"],
                    "rootHash": "root123"
                }
            }
        }

        mock_compute_hash.return_value = "computed_leaf_hash"

        index, tree_size, leaf_hash, hashes, root_hash = get_verification_proof(123456, True)

        captured = capsys.readouterr()
        assert "Computed Leaf Hash:" in captured.out


class TestDataClasses:
    """Tests for data classes."""

    def test_consistency_proof_creation(self):
        """Test ConsistencyProof dataclass creation."""
        from assignment1.merkle_proof import ConsistencyProof
        proof = ConsistencyProof(
            proof=["hash1", "hash2"],
            root1="root1_hash",
            root2="root2_hash"
        )
        assert proof.proof == ["hash1", "hash2"]
        assert proof.root1 == "root1_hash"
        assert proof.root2 == "root2_hash"

    def test_inclusion_proof_creation(self):
        """Test InclusionProof dataclass creation."""
        from assignment1.merkle_proof import InclusionProof
        proof = InclusionProof(
            leaf_hash="leaf_hash",
            proof=["hash1", "hash2"],
            root="root_hash"
        )
        assert proof.leaf_hash == "leaf_hash"
        assert proof.proof == ["hash1", "hash2"]
        assert proof.root == "root_hash"
