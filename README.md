# Rulemoor

**Confirmed Linux firewall changes, with explicit recovery.**

Rulemoor is an early single-node service for changing dedicated nftables input tables (IPv4 by default, or explicitly enabled IPv4/IPv6 dual mode). An operator previews a policy, applies it with a confirmation deadline, and confirms through fresh TLS management connections. Without confirmation, the running agent attempts to restore the preceding policy. After a process crash, it reconciles its durable journal with actual kernel rules before accepting another change. After a boot ID change, it can recreate an absent owned table from the durable confirmed policy or unfinished change’s baseline.

The practical use case is a remotely managed Linux machine where an incorrect TCP ingress rule could remove the operator's access. Rulemoor provides the change lifecycle, not a general firewall manager or a guarantee that every network failure can be repaired.

## Scope

- Strict JSON schema: default `accept`/`drop`, up to 32 ordered TCP port rules per family; established/related traffic is accepted first.
- Legacy mode owns only `ip rulemoor`; opt-in dual mode owns `ip rulemoor` plus `ip6 rulemoor`, input hook, priority 0. No arbitrary nft scripts, routing, NAT or multi-device transaction. Dual mode always accepts ICMPv6 control traffic and requires both families to confirm. [Dual-stack scope and setup](docs/DUAL_STACK.md); [review and limits](docs/DUAL_REVIEW.md). [Dual VM boot and orphan-executor validation](docs/DUAL_RECOVERY.md) adds direct fault evidence.
- CLI and TLS API with a provisioned certificate and a shared operator bearer token. No plaintext API or certificate-verification bypass in the CLI.
- Durable intent, bounded operation history, explicit confirmation/cancellation, deadline rollback and process-restart recovery.
- Bounded persisted-state validation rejects malformed snapshots before process fencing or kernel writes; the original evidence remains intact.
- Optional declared management-port preflight rejects candidates that block those declared NEW IPv4/IPv6 TCP paths; read-only foreign nftables diagnostics report supported conflicts and uncertainty. [Enable and understand the limits](docs/MANAGEMENT_PREFLIGHT.md). [Dual-family configuration and evidence](docs/DUAL_PREFLIGHT.md) keep IPv6 blocked/unknown results separate from IPv4. The [review](docs/PREFLIGHT_REVIEW.md) covers recovery despite invalid admission configuration, NEW/ESTABLISHED input analysis and same-listener TCP evidence.
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

To enable protected-port admission and foreign-rule diagnostics, provision the [management-path configuration](examples/management-paths.json) and add `--management-paths /etc/rulemoor/management-paths.json` to `serve`. Without it the report explicitly says `not_configured`; no path protection is inferred.

Each CLI invocation uses new TLS connections. Confirmation verifies operation ID, generation, candidate digest, challenge, boot ID, deadline and connection freshness. A successful legacy confirmation proves one management path only. In dual mode, a first family confirmation remains pending; only a fresh confirmation from each family commits. This proves the tested paths, not every network route. An old keepalive or TCP connection queued before application is insufficient.

## Validation and retained results

```sh
# Portable production-core and local TLS/API tests (no real kernel firewall writes).
.venv/bin/python -m tools.unit
.venv/bin/python -m tools.mutations

# macOS: immutable-source native tests + disposable real Linux kernel validation.
PYTHON=.venv/bin/python tools/validate-local
```

The one-command workflow installs checksum-pinned Colima/Lima locally if necessary and reuses an installed Docker CLI. Docker Desktop does not need to run. First-time setup downloads VM/container images. Existing running VMs are refused. See [validation methodology](docs/VALIDATION.md) for explicit toolchain overrides and cleanup behavior.

[Systemd / VM restart validation](docs/DEPLOYMENT_VALIDATION.md) · [Deployment evidence review](docs/DEPLOYMENT_REVIEW.md) · [Startup recovery review](docs/STARTUP_REVIEW.md) · [Deployment HTML report](reviews/deployment/report.html)

[Retained validation](reviews/mvp/combined.json) · [HTML report](reviews/mvp/report.html) · [measurement interpretation](docs/MEASUREMENTS.md)

macOS evidence covers portable contracts and real local TLS, using a memory backend. **Real nftables, network-failure, daemon RSS and operation timing evidence comes from Linux in a Colima VM.** These are separate scopes, not a native-platform performance comparison. All measured trials are retained; no speedup or production SLA is claimed.

## Design and limits

[Agent-assisted review](docs/AGENT_REVIEW.md) · [Pre-publication review](docs/PUBLICATION_REVIEW.md) · [Architecture](docs/ARCHITECTURE.md) · [Operations and recovery](docs/OPERATIONS.md) · [Security](SECURITY.md)

Important boundaries:

- A stopped agent has no running rollback timer. Persistent startup failure can exhaust the supplied systemd start limit and leave a pending policy installed until local recovery. Known malformed snapshots instead expose DEGRADED without automatic policy repair. The supplied systemd unit and three orderly VM stop/start scenarios (two legacy IPv4 and one partially confirmed dual deployment) are integration-tested in an isolated Linux VM. This does not establish power-loss recovery, recovery-time bounds or boot ordering on other hosts. Rules may be absent before service startup.
- Another privileged writer can ignore the advisory lock. Readback detects observed drift; it is not atomic exclusion against arbitrary root processes. Do not concurrently use another manager for the owned table.
- Table replacement does not promise preservation of counters or all existing connections. Other tables/chains can still block traffic; this table's accept cannot override their drop.
- Corrupt journals, interrupted first-time provisioning, unknown rules and failed rollback require local/operator recovery. Keep console or another independent recovery path.
- This is an early controlled-environment MVP, not a production-qualified security appliance. It has no RBAC, SSO, distributed consensus, high availability or automatic repair of foreign policy.
- Apply IDs are deduplicated within the most recent 64 retained operations. Old generations are rejected even after an ID is evicted. Cancellation/confirmation retries should inspect status after a lost response.

## License

Rulemoor's authored source and documentation are available under the [MIT License](LICENSE), copyright (c) 2026 Andrew Yuan. Third-party tools retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).

## Opt-in early policy load and interface gate

[Boot Guard MVP](docs/BOOT_GUARD.md) adds an installed production entry point and
systemd unit for a single isolated static dual-stack veth profile. It reuses
journal recovery/executor fencing, verifies both kernel policies before UP, and
records CLOSED after verified closure, or FAULTED when closure cannot be verified. The default Agent deployment is
unchanged; opt-in configuration reserves interface activation to Rulemoor.

The isolated VM suite covers actual production backend recovery-write rejection,
a delayed orphan executor, independent IPv4/IPv6 allow/deny canaries and fresh TLS,
and orderly restarts for partial-confirmation and committed states. See
[retained evidence](reviews/guard/README.md) for actual results and limitations.
This does not establish whole-host early-boot zero-gap or sudden power-loss
recovery. [Earlier design experiments](docs/BOOT_GUARD_EXPLORATION.md) and their
[review](docs/BOOT_GUARD_REVIEW.md) retain their original historical scope.
