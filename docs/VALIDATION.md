# Validation method

## Native scope

`python -m tools.unit` runs production schema/compiler/core decisions, real local TLS API/CLI transport checks, and failure/timeout handling of the validation process wrapper. Memory-backend tests deliberately isolate state-machine contracts. They do not establish nft semantics, kernel reachability or native macOS agent performance. OpenSSL is needed to create temporary test certificates, which are deleted with the temporary directory.

`python -m tools.mutations` copies source into isolated temporary directories, changes nine production decisions and requires an existing assertion to fail for each. Import/syntax failures, timeouts or a bare nonzero exit do not count as caught mutations.

## Linux scope

`tools.linux_validate` runs inside a disposable VM container. It repeats portable tests and runs real nftables/network namespace/TLS tests through the production Controller, NftBackend, service and CLI request transport. The only alternate frontend is the fault driver, which calls these same production methods and holds process boundaries for SIGKILL; it is not another recovery implementation.

The cases include:

- Kernel dry-run nonmutation, invalid-batch atomicity, unrelated-table preservation, full 32-rule compilation and ordered/default-drop readback.
- Established old keepalive versus blocked fresh connection, old-confirm rejection, timeout restoration, fresh reconnect and positive confirmation surviving its deadline.
- SIGKILL at prepared, executor intent, executor held, kernel-applied, awaiting-confirm and rollback-applied boundaries; repeated recovery and old-generation rejection.
- An inherited lock held by the actual nft binary; a killed parent with an orphan executor; verified retirement followed by a newer commit which survives delayed old release.
- Unknown foreign policy before readback or during restart recovery: DEGRADED and no blind overwrite.
- Actual TLS service restart, malformed-executor-record startup with an accessible DEGRADED status and blocked writes, graceful shutdown, pre-apply TCP backlog rejection, and SIGKILL after confirmation commit but before the HTTP response.
- Actual SQLite commit followed by an injected checkpoint-connection error, with real kernel readback and confirmation preserved past the deadline and controller reopen. Actual service-process restart is covered separately. Native tests separately inject ESRCH at both pidfd boundaries and verify permission failures remain fail-closed.
- Sixteen unauthenticated header-drip TLS connections using the default 5-second absolute lifetime: rollback still occurs, the finite batch expires and a fresh confirmation succeeds. This is not continuous-attack protection.
- Actual ENOSPC in a bounded 16 MiB tmpfs, baseline restoration after releasing reserve, durable rollback readback, state-budget refusal, corrupt-journal refusal and test mount cleanup.
- Ten timed policy changes with every trial retained, alternating confirmation/cancellation, plus worker RSS and state-directory allocation.

`RULEMOOR_FAULT` is an internal fault-injection environment variable. Never set it in a deployment; the sample unit clears it. No remote API enables fault hooks.

## One command, same snapshot

```sh
PYTHON=.venv/bin/python tools/validate-local
```

This installs checksum-pinned Colima/Lima into ignored local storage and uses an existing Docker CLI. A dedicated Colima home/profile is used by default. It starts only an absent/stopped profile; it refuses to disturb an already running one. Native and container runs receive the same immutable file snapshot and run ID. Executable Python, package configuration, Dockerfile, service unit, wrapper and toolchain lock hashes are recorded. README/results changes do not alter the executable snapshot.

Existing installations can explicitly provide all three overrides:

```sh
RULEMOOR_TOOLCHAIN=/path/to/toolchain/bin \
RULEMOOR_COLIMA_HOME=/path/to/dedicated-colima-home \
RULEMOOR_DOCKER_CONFIG=/path/to/docker-config \
PYTHON=.venv/bin/python tools/validate-local --output results/run-example
```

Do not run another project against the selected profile concurrently. Each run requires a fresh output directory. Container constraints: no network egress, no bind mounts, no privileged mode, 2 vCPU, 768 MiB memory, 128 PID limit, NET_ADMIN and SYS_ADMIN only, within the disposable VM. The extra mount capability is for isolated namespace/tmpfs tests, not a production-agent requirement. No host NIC, DNS or firewall is changed.

Nonzero exit, timeout, missing/empty evidence, run/source mismatch, OOM, source drift or cleanup failure prevents a passing receipt. SIGINT/SIGTERM trigger bounded cleanup; a forcibly killed host driver, host crash or VM-manager failure can still require manual container/VM cleanup. Raw host logs stay under ignored `results/` because they may contain local filesystem paths.

The driver verifies container exit and removal, VM stopped state, namespace/process cleanup and unchanged container-root firewall. It also requires zero workers in both test namespaces after every case, before later measurements. Fixture cleanup signals owned process groups even when their direct parent already exited; this does not authorize production to signal a PID from malformed metadata. It challenges the evidence verifier with seventeen corrupted/missing-evidence controls, including invalid old-writer identity, identical fencing policies and omitted stages. Optimized Python (`-O`/`PYTHONOPTIMIZE`) is refused because disabling assertions must not create false passing evidence. Individual test IDs are retained for both platforms. `python -m tools.audit_evidence reviews/mvp` independently rechecks current-source correspondence, raw trial summaries, run IDs, cleanup and exact HTML/JSON consistency.

Retained publication artifacts contain only structured records and the generated report, not credentials, full host logs, VM disks or container contents. An artifact's pass applies to its recorded source snapshot; later executable changes require a new run.

## Remote CI

A manual-only GitHub Actions workflow repeats portable contracts on Linux/macOS. It is not the real-kernel validation and is not required by the local workflow. It has not been dispatched for this MVP; no remote CI pass is claimed. Actions are pinned and the workflow has read-only permissions.
