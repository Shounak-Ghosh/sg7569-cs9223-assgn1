#!/bin/bash

# --- Automated Python Code Quality and Security Analysis ---

# This script executes standard Python development tools:
# 1. ruff format: Code formatting
# 2. ruff check: Linting and style checking
# 3. pylint: Static analysis and score reporting
# 4. mypy: Static type checking
# 5. bandit: Security analysis

# Exit immediately if a command exits with a non-zero status
# NOTE: We use '|| true' on analysis commands to prevent exiting if errors are found,
# as linters return non-zero on issues, but we still want all reports generated.
set -e

# Define source files for mypy (assuming these are the relevant files)
MYPY_FILES="main.py merkle_proof.py util.py"

ruff format
echo "Ruff formatting complete."

ruff check -o ruff.output.txt || true
echo "Ruff check complete. See ruff.output.txt for details."

pylint . --output pylint.output.txt || true
echo "Pylint analysis complete. See pylint.output.txt for details."

echo "mypy Files: ${MYPY_FILES}"
mypy ${MYPY_FILES} > mypy.output.txt || true
echo "Mypy type check complete. See mypy.output.txt for details."


bandit -r . -o bandit-output.txt -f txt || true
echo "Bandit security scan complete. See bandit-output.txt for details."

echo ""
echo "ALL CODE QUALITY CHECKS COMPLETED SUCCESSFULLY."
echo "Review the output files for detailed reports."
