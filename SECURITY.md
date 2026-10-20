# Security and support boundary

Rulemoor 0.1 is an early controlled-environment MVP. Treat firewall administration credentials as root-equivalent for the table it manages. Keep an independent console/recovery channel and deploy only after validating the target environment.

The API requires TLS and a private bearer-token file. The CLI verifies the server certificate. There is one trusted-operator role; no RBAC, SSO, tenant isolation, replay-resistant per-request signatures, credential rotation service or distributed authorization is implemented. Do not expose the service directly to an untrusted network. Revoking a token requires provisioning a replacement and restarting the service.

State, key and token directories must be private. Status/history contain operational configuration and confirmation challenges; treat responses as sensitive even though default logs omit bodies, credentials and client addresses. Reports from the bundled tests contain documentation-range test addresses only. Actual operational reports should not be uploaded without review.

The owned table is fixed. Policy inputs are constrained and never passed to a shell. Actual commands have time bounds. Connection count, 2-second inactivity time, 5-second absolute connection lifetime, body size, policy rules and retained history are bounded. A finite batch of header-trickle connections expires; an attacker continuously replacing connections can still exhaust admission capacity. Excess connections are closed; this is resource admission, not comprehensive denial-of-service resistance.

No advisory lock protects against an arbitrary root process. Foreign-policy detection blocks unsafe automatic overwrites when observed; it cannot atomically exclude other privileged managers. Unknown state requires operator action. The supplied service unit is untested packaging, not proof of production hardening.

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/andrew29mo/rulemoor/security/advisories/new). Do not post tokens, private keys or real operational state in public issues. Secret scanning, push protection and Dependabot are enabled; they do not establish that every vulnerability or secret format will be detected.

The main branch blocks force pushes and deletion, including administrators. The owner may push directly to preserve single-maintainer operation; mandatory PR approvals and manual-only CI checks are not merge gates. Actions tokens are read-only and cannot approve PRs. Only the two explicitly SHA-pinned checkout/setup-python actions are allowed. All external contributors require approval for eligible fork PR workflows; the current portable workflow is manual-only and runs no external PR trigger.
