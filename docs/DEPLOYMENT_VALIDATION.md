# Installed systemd service and VM restart validation

This suite runs the production service under actual systemd in a dedicated Colima Linux VM, outside containers. The service's firewall writes are confined to the disposable `rm_deployment` network namespace. It complements the portable macOS and containerized Linux suite; it does not turn macOS into a supported agent host.

## Run and audit

Use a previously provisioned, stopped, dedicated VM with no running containers or existing Rulemoor installation. The selected VM is restarted twice. Do not share the selected profile with another active task.

```sh
PYTHON=.venv/bin/python tools/validate-deployment \
  --toolchain /path/to/pinned/toolchain/bin \
  --colima-home /path/to/dedicated-colima-home \
  --profile relay --allow-vm-restarts \
  --output results/deployment-example

.venv/bin/python -m tools.audit_deployment results/deployment-example
```

The existing pinned Colima/Lima tools are reused. Python's `build` frontend is required locally; build isolation resolves setuptools. The VM needs Ubuntu/Debian apt repositories and Python >=3.12; the workflow installs the venv/nftables/iproute2/OpenSSL prerequisites in that VM. These prerequisites are not a claim of distribution-wide support.

The runner makes an immutable executable snapshot, builds a wheel, installs it in `/opt/rulemoor/venv`, and compares installed module bytes with that snapshot using an isolated (`-I`, working directory `/`) interpreter query. The returned origin must be the venv site-packages directory, and exported module hashes must match the source manifest; checkout self-comparison is rejected. It installs the exact `deploy/rulemoor.service`, verifies it with `systemd-analyze`, and checks the running unit's restart, cgroup, namespace, capability and sandbox properties. A fixture-only dependency creates the namespace after each boot; a drop-in selects it and enables memory accounting. The production bind address remains loopback, so these tests establish fresh TLS access inside the namespace, not external network routing or WAN reachability.

## Cases and distinguishing observations

1. **Installed unit:** actual systemd PID 1, installed package byte equality, exact production unit digest, sandbox/capability checks and TLS readiness.
2. **Malformed snapshot:** write a JSON list into the actual SQLite snapshot while stopped, start the installed unit and require DEGRADED, blocked mutation, unchanged kernel/data and stable invocation/restart count over a 2.2-second observation. Preserve private evidence, stop writers, then explicitly reprovision the disposable baseline and rotate credentials for subsequent cases. No production automatic repair is claimed.
3. **Persistent startup failure:** apply an unconfirmed candidate, withhold the TLS key and kill MainPID. The real installed ExecStart repeatedly exits before recovery and must hit the production start limit. A current-boot structured systemd journal receipt must identify the rate-limit refusal after this fault began; some versions retain `Result=exit-code` rather than `start-limit-hit`. Retain failed/stable unit properties, an unchanged pending journal and candidate kernel policy. Restoring the key alone must not bypass the rate limit. Repair plus explicit reset/start must restore the baseline; stale requests must not alter a newer pending or committed policy. This is not a segmentation-fault or uninterruptible-I/O test.
4. **Agent SIGKILL:** with an unconfirmed policy active, kill only MainPID; observe systemd's new invocation/PID and increased restart count, baseline readback and fresh TLS readiness. Submit a newer change, challenge it with old confirmation/cancel/apply requests while it is pending, then confirm and challenge again.
5. **Old executor:** a test-only drop-in temporarily enables the production held-executor hook. Observe its real process identity, remove the test override, kill MainPID and verify cgroup cleanup/recovery. A distinct newer policy must survive releasing the old hook and stale requests. This is explicitly fault injection, not an ordinary deployment setting.
6. **Pending boot preparation:** install an unconfirmed candidate, then stop the agent with a temporary SIGKILL/no-restart override. Verify its journal is still pending and the candidate is still in the kernel. After reboot, the namespace bootstrap reads a safe projection of the durable journal before starting the agent; it must still exactly match the stopped pending state. Remove the override before restarting the VM. This prevents a graceful shutdown rollback from masquerading as boot recovery.
7. **Pending VM boot:** orderly VM stop/start, changed kernel boot ID, namespace created with no owned table before the agent starts, enabled unit starts automatically, baseline reconstructed and generation advanced. Retain the journal before the agent starts, then the actual kernel/generation and rejected request paths while challenging a newer pending and committed policy with pre-boot requests.
8. **Committed VM boot:** a second orderly VM stop/start must recreate the confirmed policy and advance the generation. An old base is rejected. A subsequently installed foreign table is retained with DEGRADED status after service restart.
9. **Cleanup:** disable/remove the service and fixture, remove namespace workers, credentials, private state, installed package and source snapshot; verify the VM root firewall is unchanged and stop the VM.

Nonzero commands, timeout, missing cases/stages, changed sources, unchanged boot identity, altered pre-agent journal, stale kernel output, nonfinite/inconsistent measurements, wrong process identity or cleanup failure cannot produce a passing report. Eighteen deliberate evidence-corruption controls challenge the verifier. JSON and HTML are generated from the same observations and rechecked byte-for-byte by the auditor. Raw host logs and private operational receipts remain ignored/local; shared artifacts exclude credentials and confirmation challenges. Interrupted VM-manager/host failures can require manual recovery; stopping the driver forcibly is not a guaranteed cleanup path.

## Measurements and limits

The JSON retains raw kernel policies, generations, process/boot identities, restart counts, daemon RSS/VmHWM and systemd cgroup memory. It also records one Agent-SIGKILL-to-observed-TLS-readiness interval and one host-observed stop/start/validation interval for each VM case. Raw monotonic nanosecond endpoints allow recomputation of those intervals. TLS readiness is timestamped immediately after the successful probe, before the separate baseline readback; the latter endpoint is also retained. These include probing, SSH, VM control and assertion overhead; they are neither exact service-only boot latency nor recovery-time upper bounds. Memory measurements are observations, not continuous peak sampling of the entire deployment. Each sample retains stable MainPID/start-time/boot identity, systemd invocation, executable entrypoint, cgroup and matching namespace identity. If the process changes during sampling, the sample fails. The committed-boot sample is taken before the separate foreign-policy restart. Agent VmHWM excludes nft children, clients and VM memory; cgroup memory has a different scope and includes service children and charged memory. VM RAM is not reported as daemon RSS.

These measurements come from VM system services (configured 4 vCPU / 6 GiB), separate from the 2-vCPU / 768-MiB container operation measurements in `MEASUREMENTS.md`. Python/nftables/systemd versions are retained separately. Do not interpret differences between those environments or runs as performance improvements.

**Power-loss recovery is not tested.** VM stop/start uses orderly shutdown, not abrupt power removal or storage fault injection. Systemd restart limits, boot dependencies and storage availability can delay/prevent recovery. There is no running rollback timer while the agent is stopped. The owned rules can be absent before service startup, so this is not fail-closed early boot or uninterrupted management access. Other hosts, architectures, firewall managers and storage stacks require their own validation.

[Evidence review and corrections](DEPLOYMENT_REVIEW.md) · [Retained JSON](../reviews/deployment/deployment.json) · [HTML report](../reviews/deployment/report.html) · [Attempt history](../reviews/deployment/attempts.json)

## Retained observations

Run `63577fe5d44f6b6b`, source `8ec11da5478d2bada0534e4143e43e0b24f39cec0e06185e0ce81bf9cd4fcdcc`. Kernel 6.8.0-117-generic/aarch64, Python 3.12.3, systemd 255 (255.4-1ubuntu8.15), nftables v1.0.9 (Old Doc Yak #3). All nine case groups and eighteen evidence-corruption controls passed. The installed origin is the venv site-packages directory, with all production module hashes matched against this source.

The malformed JSON-list snapshot produced DEGRADED with unchanged kernel policy and preserved original data. The persistent missing-key fault reached the configured start limit: MainPID=0, ActiveState=failed, Result=exit-code, NRestarts=6. A current-boot, post-fault journal receipt records the refused start. No further restart was observed for **2.21 s**. The journal remained pending and the candidate remained installed while stopped. Fixing the cause and explicitly resetting/starting restored the baseline; stale requests could not overwrite a newer change. This establishes neither an independent rollback service nor automatic recovery of an untrusted journal.

One separate Agent SIGKILL trial reached observed fresh TLS readiness in **1111.2 ms**. Baseline readback has its own subsequent timestamp. The host-observed orderly VM stop/start plus validation intervals were **12.86 s** (pending) and **12.35 s** (committed). Each is one observation with documented probe/control overhead, not a recovery upper bound. The raw `vm_uptime_after_validation_seconds` is kernel uptime after the case, not Agent startup latency.

| Observation stage | Agent RSS MiB | Agent VmHWM MiB | Service cgroup MiB |
|---|---:|---:|---:|
| setup | 22.17 | 22.17 | 10.65 |
| poisoned_journal | 22.25 | 22.25 | 10.72 |
| restart_limit | 22.88 | 22.88 | 11.61 |
| crash | 22.81 | 22.81 | 11.51 |
| after_pending_boot | 22.78 | 22.78 | 11.93 |
| after_committed_boot | 22.17 | 22.17 | 10.99 |

The restart-limit memory sample is taken after local recovery, not while no process is running. Every sample is attributed to a stable process/invocation in the namespace. Cgroup charge accounting and RSS are not additive/interchangeable or total VM memory. No CPU/log-exhaustion measurement was performed. Native segmentation faults, uninterruptible I/O and power-loss recovery were not tested. Failed/superseded attempts remain visible.
