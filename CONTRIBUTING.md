# Contributing

Thank you for contributing to this repository. This document outlines the expectations and the simple processes we ask contributors to follow for submitting pull requests, reporting issues, adhering to code style, and providing tests.

## Table of contents

- Reporting issues
- Submitting pull requests (PRs)
- Simple review process
- Code style and quality
- Testing requirements
- Contributor expectations
- Quick checklist

## Reporting issues

- Search existing issues first to avoid duplicates.
- When opening a new issue, include a clear title and a concise description of the problem or feature request. Provide:
	- Steps to reproduce (for bugs)
	- Expected vs actual behavior
	- Relevant environment information (Python version, OS) if applicable
	- Small, self-contained examples or stack traces when possible

## Submitting pull requests (PRs)

1. Fork the repository and create a branch from `main` named with the pattern `topic/short-description` or `fix/short-description`.
2. Make focused, small commits with clear messages. Prefer multiple small commits for logical steps; we may squash on merge.
3. Run tests and linters locally before pushing.
4. Push your branch to your fork and open a PR against this repository's `main` branch.
5. In the PR description include:
	 - What the change does and why
	 - Any relevant issue number (use `#123` to link)
	 - How to test the change (commands to run, example inputs)

PR Template suggestions (use in the PR description):

- Summary of changes
- Related issue (if any)
- How to test / verification steps
- Checklist: tests added, linting passed, documentation updated

## Simple review process

- A maintainer or reviewer will look at the PR for clarity, correctness, and CI results.
- Reviewers will leave comments or request changes if something needs fixing.
- When at least one approval is given and CI checks pass, the PR can be merged by a maintainer.
- Merge strategy: maintainers may squash commits to keep history tidy unless a linear history is desired.

## Code style and quality

- This project follows standard Python conventions (PEP 8) unless otherwise noted.
- Use an automatic formatter (black) and a linter (flake8/ruff) if available. Run them before opening a PR.
- Naming, docstrings, and typing:
	- Use descriptive names for functions and variables.
	- Add docstrings for public functions/classes.
	- Add type hints where helpful.

If you are unsure about style, open a draft PR and ask for guidance.

## Testing requirements

- All new features and bug fixes should be accompanied by tests where feasible.
- Tests should be placed in the test directory (or follow the repository's existing test conventions).
- Run the test suite locally and ensure all tests pass before submitting your PR. If a test harness or command exists (e.g., `pytest`), include the command in your PR description.

If the repository includes a CI pipeline, your PR must pass the pipeline checks before it will be merged.

## Contributor expectations

- Keep changes small and focused. Large or broad refactors should be discussed in an issue first.
- Be responsive to review comments and willing to make follow-up commits to address feedback.
- Follow respectful and constructive communication.
- By contributing, you agree that your contributions will be made under the project license.

## Quick checklist (before creating a PR)

- [ ] I searched for existing issues/PRs
- [ ] My branch is up to date with `main`
- [ ] I ran tests locally and they pass
- [ ] I ran code formatters/linters and fixed issues
- [ ] My PR description explains why the change is needed and how to test it

## Thank you

Thank you for taking the time to contribute. If you have questions about the process, open an issue or contact a maintainer.
