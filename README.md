# Rulemoor

**Confirmed Linux firewall changes, with explicit recovery.**

Rulemoor is an early single-node service for changing a dedicated nftables IPv4 input table. An operator previews a policy, applies it with a confirmation deadline, and confirms through a fresh TLS management connection. Without confirmation, the running agent attempts to restore the preceding policy. After a process crash, it reconciles its durable journal with actual kernel rules before accepting another change.

The practical use case is a remotely managed Linux machine where an incorrect TCP ingress rule could remove the operator's access. Rulemoor provides the change lifecycle, not a general firewall manager or a guarantee that every network failure can be repaired.

## Scope

- Strict JSON schema: default `accept`/`drop`, up to 32 ordered TCP port rules; established/related traffic is accepted first.
- Exactly one table, `ip rulemoor`, input hook, priority 0. No arbitrary nft scripts, routing, NAT, IPv6 or multi-device transaction.
- CLI and TLS API with a provisioned certificate and a shared operator bearer token. No plaintext API or certificate-verification bypass in the CLI.
- Durable intent, bounded operation history, explicit confirmation/cancellation, deadline rollback and process-restart recovery.
- Unknown rules or uncertain ownership become `DEGRADED`, which blocks further changes rather than blindly overwriting them.

## Quick start

Python 3.12 is required. The agent additionally requires Linux with CLOCK_BOOTTIME, pidfd support, nftables, and permission to manage its network namespace. The CLI works on macOS and Linux.

From a checkout, commands work without installing Python runtime dependencies:

```sh
python3.12 -m venv .venv
.venv/bin/python -m rulemoor.cli --help
.venv/bin/python -m rulemoor.service --help
```

On a disposable Linux machine or network namespace, provision a private state directory, TLS certificate/key and a random token. See [installation](docs/OPERATIONS.md) before using a real host. The validation workflow creates its own disposable environment; it never changes the macOS host firewall.

```sh
# Linux, with the required privileges; refuses an existing table or journal.
.venv/bin/python -m rulemoor.service --state /var/lib/rulemoor init --policy examples/baseline.json
.venv/bin/python -m rulemoor.service --state /var/lib/rulemoor serve \
  --listen 192.0.2.2 --port 18443 \
  --cert /etc/rulemoor/server.pem --key /etc/rulemoor/server.key \
  --token-file /etc/rulemoor/token
```

`192.0.2.2` is an example address. The certificate must match the actual management address. Provision and protect credentials outside Git.

```sh
.venv/bin/python -m rulemoor.cli --url https://192.0.2.2:18443 \
  --ca /secure/server-ca.pem --token-file /secure/operator-token plan examples/candidate.json

# Read the current generation from plan/status. This example assumes generation 0.
.venv/bin/python -m rulemoor.cli --url https://192.0.2.2:18443 \
  --ca /secure/server-ca.pem --token-file /secure/operator-token \
  apply examples/candidate.json --op change-001 --generation 0 --window 30

.venv/bin/python -m rulemoor.cli --url https://192.0.2.2:18443 \
  --ca /secure/server-ca.pem --token-file /secure/operator-token \
  confirm --op change-001 --generation 1
```

Each CLI invocation uses new TLS connections. Confirmation verifies operation ID, generation, candidate digest, challenge, boot ID, deadline and connection freshness. A successful confirmation proves one management path only. An old keepalive or TCP connection queued before application is insufficient.

## Validation and retained results

```sh
# Portable production-core and local TLS/API tests (no real kernel firewall writes).
.venv/bin/python -m tools.unit
.venv/bin/python -m tools.mutations

# macOS: immutable-source native tests + disposable real Linux kernel validation.
PYTHON=.venv/bin/python tools/validate-local
```

The one-command workflow installs checksum-pinned Colima/Lima locally if necessary and reuses an installed Docker CLI. Docker Desktop does not need to run. First-time setup downloads VM/container images. Existing running VMs are refused. See [validation methodology](docs/VALIDATION.md) for explicit toolchain overrides and cleanup behavior.

[Retained validation](reviews/mvp/combined.json) · [HTML report](reviews/mvp/report.html) · [measurement interpretation](docs/MEASUREMENTS.md)

macOS evidence covers portable contracts and real local TLS, using a memory backend. **Real nftables, network-failure, daemon RSS and operation timing evidence comes from Linux in a Colima VM.** These are separate scopes, not a native-platform performance comparison. All measured trials are retained; no speedup or production SLA is claimed.

## Design and limits

[Agent-assisted review](docs/AGENT_REVIEW.md) · [Pre-publication review](docs/PUBLICATION_REVIEW.md) · [Architecture](docs/ARCHITECTURE.md) · [Operations and recovery](docs/OPERATIONS.md) · [Security](SECURITY.md)

Important boundaries:

- A stopped agent has no running rollback timer. Recovery requires restarting it. A service-manager example is supplied, but systemd packaging, whole-host reboot and power loss are not integration-tested.
- Another privileged writer can ignore the advisory lock. Readback detects observed drift; it is not atomic exclusion against arbitrary root processes. Do not concurrently use another manager for the owned table.
- Table replacement does not promise preservation of counters or all existing connections. Other tables/chains can still block traffic; this table's accept cannot override their drop.
- Corrupt journals, interrupted first-time provisioning, unknown rules and failed rollback require local/operator recovery. Keep console or another independent recovery path.
- This is an early controlled-environment MVP, not a production-qualified security appliance. It has no RBAC, SSO, distributed consensus, high availability or automatic repair of foreign policy.
- Apply IDs are deduplicated within the most recent 64 retained operations. Old generations are rejected even after an ID is evicted. Cancellation/confirmation retries should inspect status after a lost response.

## License status

**No project license has been selected.** No `LICENSE` file or open-source grant is included. The repository is maintained privately pending a separate release decision. Third-party tools retain their respective licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).
