## Security Policy

This document describes how to report security vulnerabilities, which versions are supported, and how security updates are handled for this project.

### Supported Versions

- Active development branch: `main` — receives fixes and updates.
- Releases: only the latest tagged release is actively supported. Critical/security fixes may be backported to earlier releases at the maintainers' discretion.

If you depend on an older release and require a security backport, please contact the maintainers (see Contact below) with details and we will evaluate support on a case-by-case basis.

### Reporting a Vulnerability

Please do NOT open public GitHub issues describing security vulnerabilities. Public disclosure may put users at risk.

Preferred ways to report a vulnerability:

1. GitHub Security Advisories
	- On GitHub, open a private Security Advisory for this repository so maintainers and contributors can coordinate a fix privately.

2. Email
	- If you prefer email, send a report to: <security@replace-with-your-email.example>
	- Include: affected version(s), a short description of the vulnerability, steps to reproduce or a proof-of-concept, and any suggested mitigations.

3. PGP (optional)
	- If you need to send sensitive exploit details securely, you may encrypt the report with the project maintainer's PGP key. (Add PGP key or contact for details.)

What to include in your report

- Affected version(s) or commit hashes
- Clear description of the issue and impact
- Reproduction steps or a minimal PoC
- Any suggested remediation or patch

If you report a vulnerability, we will acknowledge receipt and keep you informed while we triage and fix the issue.

### Response Process and Timelines

We follow a responsible disclosure process:

- Acknowledgement: We aim to acknowledge new reports within 72 hours.
- Triage: We will assess severity, reproducibility, and impact.
- Fix: For high or critical issues we aim to produce a patch as soon as possible and, when feasible, within 30 days. Timelines depend on complexity and available maintainers.
- Disclosure: We will coordinate disclosure with the reporter. Public disclosure will normally occur only after a fix or mitigation is available, unless the reporter requests a different timeline.

If you believe an issue is being handled too slowly, please follow up using the contact methods above.

### How Security Updates Are Released

- Patches for vulnerabilities will be released as commits to `main` and as a new patch release (tag) where appropriate.
- For critical vulnerabilities, we will prioritize an urgent patch and a new release; we may publish mitigation guidance in a private advisory before public release if required for safety.
- Notifications: Security fixes will be noted in the changelog/release notes for the repository and tagged releases.

### Credit

We appreciate and welcome responsible disclosure. If you wish, we will credit you in the release notes for a disclosed and fixed vulnerability unless you request anonymity.

### Contact

Replace the placeholder email below with the preferred private contact point for security reports:

security contact: <security@replace-with-your-email.example>

If you prefer, use GitHub's private Security Advisory system for this repository.

---

Notes:

- Replace the placeholder email and (optionally) add a PGP key or other contact method before publishing.
- If you want a stricter supported-versions policy (for example, a 12-month support window for releases), tell me what timeframe you want and I will update this file accordingly.
>