# sg7569-cs9223-assgn1
Code for CS9223 Assignment 1 with Prof. Justin Cappos

# Assignment 1 Notes
- Used Go for installations
- [Signing and uploading blobs w/ cosign](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
- `cosign sign-blob artifact.md --bundle artifact.bundle`
    - This command automatically uploads to Rekor:
        - https://rekor.sigstore.dev/api/v1/log?logIndex=495027577
        - https://search.sigstore.dev/?logIndex=495027577
- `python main.py --inclusion 495027577 --artifact artifact.md`
- `python main.py --consistency --tree-id 1193050959916656506 --tree-size 373980633 --root-hash cf2af3bef55a119948a8e5c13cce1ea2c0807cdf400cb68ef21067e56dc3a2ba`

# Assignment 2 Notes
- `ruff format`
- `ruff check -o ruff.output.txt`
- `pylint . --output pylint.output.txt`
- `mypy main.py merkle_proof.py util.py > mypy.output.txt`
- `bandit -r . -o bandit-output.txt -f txt`

# Assignment 4 Notes
- Used pip requirements.txt for cyclone SBOM, not poetry
- Verify attestation: `cosign verify-blob-attestation \
  --bundle dist/sg7569_cs9223_assgn1-0.1.0-py3-none-any.whl.bundle \
  dist/sg7569_cs9223_assgn1-0.1.0-py3-none-any.whl \
  --certificate-identity [email address here] \
  --certificate-oidc-issuer https://github.com/login/oauth \
  --type cyclonedx \
  --check-claims`

    - Output: 
        setting TUF refresh period to 24h0m0s
        Verified OK
