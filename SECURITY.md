# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Private Vulnerability Reporting: <https://github.com/nubian-ibex/amivuln/security/advisories/new>. Do not open public issues for security problems.

## Response targets

- Acknowledgement within 72 hours.
- Triage within 7 days.
- Coordinated disclosure within 90 days of the report, sooner if a fix ships earlier.

## Supported versions

Pre-1.0: only the latest release receives security fixes. See the [support policy](https://ibexwall.com/amivuln/support.html) for the 1.0 plan, the MSRV rules and what is a contract.

## Release integrity

Releases carry GitHub artifact attestations, a cosign keyless signature over `SHA256SUMS` and CycloneDX SBOMs. See the README for verification commands.
