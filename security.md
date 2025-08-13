# Security Policy

We appreciate responsible disclosure and good-faith research. This project does
not process production secrets; however, downstream users may integrate it into
CI or deployment pipelines, so please report any issues privately.

## Supported Versions
- **main** branch: actively supported
- Tagged releases ≥ v0.1.0

## How to Report a Vulnerability
- Prefer **GitHub Security Advisories** (Private vulnerability reporting) on this repo.
- Or contact via the form at **bryansbarrett.dev** with subject “Security – Drift Sonar”.
- Please do not open a public issue for vulnerabilities.

## Scope
In-scope:
- Code execution vulnerabilities in CLI or GitHub Action
- Credential or token leakage through logs
- Tampering or falsification of EchoFingerprint / log outputs
- Workflow permission escalation

Out-of-scope:
- Social engineering, DDoS, spam
- Issues requiring physical access
- 3rd-party package vulnerabilities without a PoC against this project

## Safe Harbor
We will not pursue legal action for good-faith, non-disruptive testing that
respects privacy and data protection, stays within the scope above, and avoids
degrading service for others.

## Coordinated Disclosure
Please allow a reasonable window to triage and remediate before public
disclosure. We’re happy to credit reporters in the release notes.
