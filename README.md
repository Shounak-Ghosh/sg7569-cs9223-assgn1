# SG7569 — CS9223 Assignment 1

[![CI](https://github.com/Shounak-Ghosh/sg7569-cs9223-assgn1/actions/workflows/ci.yml/badge.svg)](https://github.com/Shounak-Ghosh/sg7569-cs9223-assgn1/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Shounak-Ghosh/sg7569-cs9223-assgn1/badge)](https://scorecard.dev/viewer/?uri=github.com/Shounak-Ghosh/sg7569-cs9223-assgn1)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11946/badge)](https://www.bestpractices.dev/projects/11946)

A small toolkit and reference implementation for verifying Rekor transparency log entries
using Merkle proofs and offline verification. This repository contains the code used for
assignment 1 of the CS9223 course (software supply chain security).

## Project contents

- `assignment1/` — Primary assignment code and scripts.
	- `main.py` — Command-line Rekor transparency log verifier (inclusion, checkpoint, consistency).
	- `merkle_proof.py`, `util.py` — Helper modules for hashing, proof verification and signature checks.
	- `artifact.bundle` — Example artifact bundle used by some of the verification helpers.

## Requirements & Dependencies

- Python: supported Python versions are >= 3.12 (see `pyproject.toml`).
- Runtime dependencies (declared in `pyproject.toml`):
	- `cryptography>=46.0.1`
	- `requests>=2.32.5`

Development tools (optional) are listed under the `dev` dependency group in
`pyproject.toml` and include `bandit`, `mypy`, `pylint`, and `ruff`.

## Installation

1. Install uv (package manager): 
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

1. Setup and activate a virtual environment (recommended):

```bash
# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv sync
```

## Usage

The main entrypoint for the assignment tools is `assignment1/main.py`. Typical commands:

- Fetch and print the latest Rekor checkpoint:

```bash
python assignment1/main.py --checkpoint
```

- Verify inclusion of an artifact using a Rekor log index and a local artifact file:

```bash
python assignment1/main.py --inclusion 12345 --artifact path/to/artifact.file
```

- Verify consistency between a previous checkpoint and the latest Rekor checkpoint:

```bash
python assignment1/main.py --consistency --tree-id <TREE_ID> --tree-size <SIZE> --root-hash <ROOT>
```

Use `-d` / `--debug` with any command to enable verbose output for troubleshooting.

## Notes and assumptions

- The code uses the public Rekor instance endpoints that are referenced in
	`assignment1/main.py`. Network access is required to fetch entries and proofs.
- The repository expects Python 3.12+ (see `pyproject.toml`); if you use a different
	Python version, some features or type checks may behave differently.
- This README provides quick usage. For implementation details, consult the source
	files in `assignment1/` (notably `main.py`, `merkle_proof.py`, and `util.py`).

## License

This project is provided under the license found in the repository `LICENSE` file.

## Contact / Questions

If you need clarifications about the assignment or the code, open an issue in the
repository or contact the maintainer listed in the repository metadata.

