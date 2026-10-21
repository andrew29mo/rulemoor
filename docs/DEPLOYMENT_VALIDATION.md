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

The configured [management diagnostic scenario](MANAGEMENT_PREFLIGHT.md) runs immediately after setup, before the existing recovery cases. It enables the production `--management-paths` argument using a fixture-only service drop-in, refuses an own-policy block, diagnoses real foreign input drops at priorities -100 and 10, preserves foreign rules and requires fresh TLS confirmation. Its TCP listener/probes are namespace-local. Each foreign-drop observation requires the same live listener and success → timeout → success after removing only the fixture table; refusal is not evidence of a drop. Missing/null management configuration is separately introduced while a change is pending, then MainPID is SIGKILLed: startup must restore baseline before refusing API admission. Configuration repair/reset/start must recover service. It removes the configuration override and disposable foreign table before the recovery cases. All eleven groups are required.

1. **Installed unit:** actual systemd PID 1, installed package byte equality, exact production unit digest, sandbox/capability checks and TLS readiness.
2. **Configured management diagnostics:** production service with declared ports, rejected own-policy block, ordered allow, real TCP probes against earlier/later foreign drops, conservative unsupported-condition diagnosis, unchanged foreign rules and old/fresh TLS confirmation. The same group includes missing/null admission-configuration recovery through the installed entrypoint; its supported argument override is removed before the other recovery cases.
3. **Fresh dual-stack slice:** actual installed entrypoint over IPv4/IPv6 static veth peers; refused legacy adoption, second-family rejected-batch nonmutation, old/fresh transport checks, repeated IPv4 partial confirmation while fresh IPv6 is blocked, whole-policy timeout rollback, two-family commit, neighbour discovery, partial-confirmation SIGKILL recovery, stale requests, foreign-rule preservation and explicit client/veth cleanup. It restores the legacy fixture before the following VM reboot tests. See [dual-stack scope](DUAL_STACK.md).
4. **Malformed snapshot:** write a JSON list into the actual SQLite snapshot while stopped, start the installed unit and require DEGRADED, blocked mutation, unchanged kernel/data and stable invocation/restart count over a 2.2-second observation. Preserve private evidence, stop writers, then explicitly reprovision the disposable baseline and rotate credentials for subsequent cases. No production automatic repair is claimed.
5. **Persistent startup failure:** apply an unconfirmed candidate using the legal operation ID `initial`, withhold the TLS key and kill MainPID. The real installed ExecStart repeatedly exits before recovery and must hit the production start limit. A current-boot structured systemd journal receipt must identify the rate-limit refusal between this fault starting and the failed-state observation beginning; some versions retain `Result=exit-code` rather than `start-limit-hit`. Retain failed/stable unit properties, an unchanged pending journal and candidate kernel policy. Restoring the key alone must not bypass the rate limit. Repair plus explicit reset/start must restore the baseline; stale requests must not alter a newer pending or committed policy. This is not a segmentation-fault or uninterruptible-I/O test.
6. **Agent SIGKILL:** with an unconfirmed policy active, kill only MainPID; observe systemd's new invocation/PID and increased restart count, baseline readback and fresh TLS readiness. Submit a newer change, challenge it with old confirmation/cancel/apply requests while it is pending, then confirm and challenge again.
7. **Old executor:** a test-only drop-in temporarily enables the production held-executor hook. Observe its real process identity, remove the test override, kill MainPID and verify cgroup cleanup/recovery. A distinct newer policy must survive releasing the old hook and stale requests. This is explicitly fault injection, not an ordinary deployment setting.
8. **Pending boot preparation:** install an unconfirmed candidate, then stop the agent with a temporary SIGKILL/no-restart override. Verify its journal is still pending and the candidate is still in the kernel. After reboot, the namespace bootstrap reads a safe projection of the durable journal before starting the agent; it must still exactly match the stopped pending state. Remove the override before restarting the VM. This prevents a graceful shutdown rollback from masquerading as boot recovery.
9. **Pending VM boot:** orderly VM stop/start, changed kernel boot ID, namespace created with no owned table before the agent starts, enabled unit starts automatically, baseline reconstructed and generation advanced. Retain the journal before the agent starts, then the actual kernel/generation and rejected request paths while challenging a newer pending and committed policy with pre-boot requests.
10. **Committed VM boot:** a second orderly VM stop/start must recreate the confirmed policy and advance the generation. An old base is rejected. A subsequently installed foreign table is retained with DEGRADED status after service restart.
11. **Cleanup:** disable/remove the service and fixture, remove namespace workers, credentials, private state, installed package and source snapshot; verify the VM root firewall is unchanged and stop the VM.
Nonzero commands, timeout, missing cases/stages, changed sources, unchanged boot identity, altered pre-agent journal, stale kernel output, nonfinite/inconsistent measurements, wrong process identity or cleanup failure cannot produce a passing report. Thirty-seven deliberate evidence-corruption controls challenge the verifier. JSON and HTML are generated from the same observations and rechecked byte-for-byte by the auditor. Raw host logs and private operational receipts remain ignored/local; shared artifacts exclude credentials and confirmation challenges. Interrupted VM-manager/host failures can require manual recovery; stopping the driver forcibly is not a guaranteed cleanup path.

## Measurements and limits

The JSON retains raw kernel policies, generations, process/boot identities, restart counts, daemon RSS/VmHWM and systemd cgroup memory. It also records one Agent-SIGKILL-to-observed-TLS-readiness interval and one host-observed stop/start/validation interval for each VM case. Raw monotonic nanosecond endpoints allow recomputation of those intervals. TLS readiness is timestamped immediately after the successful probe, before the separate baseline readback; the latter endpoint is also retained. These include probing, SSH, VM control and assertion overhead; they are neither exact service-only boot latency nor recovery-time upper bounds. Memory measurements are observations, not continuous peak sampling of the entire deployment. The diagnostic and repaired-service samples must match the setup boot, and the diagnostic sample must match its observed invocation. Each sample retains stable MainPID/start-time/boot identity, systemd invocation, executable entrypoint, cgroup and matching namespace identity. If the process changes during sampling, the sample fails. The committed-boot sample is taken before the separate foreign-policy restart. Agent VmHWM excludes nft children, clients and VM memory; cgroup memory has a different scope and includes service children and charged memory. VM RAM is not reported as daemon RSS.

These measurements come from VM system services (configured 4 vCPU / 6 GiB), separate from the 2-vCPU / 768-MiB container operation measurements in `MEASUREMENTS.md`. Python/nftables/systemd versions are retained separately. Do not interpret differences between those environments or runs as performance improvements.

**Power-loss recovery is not tested.** VM stop/start uses orderly shutdown, not abrupt power removal or storage fault injection. Systemd restart limits, boot dependencies and storage availability can delay/prevent recovery. There is no running rollback timer while the agent is stopped. The owned rules can be absent before service startup, so this is not fail-closed early boot or uninterrupted management access. Other hosts, architectures, firewall managers and storage stacks require their own validation.

[Evidence review and corrections](DEPLOYMENT_REVIEW.md) · [Retained JSON](../reviews/deployment/deployment.json) · [HTML report](../reviews/deployment/report.html) · [Attempt history](../reviews/deployment/attempts.json)

## Retained observations

Run `6e80d14cf5601c9f`, source `2173a5bb28d7610399e9d5479fb68e24d0eff6bf26c28fd84fc22acef8a4bb99`. Kernel 6.8.0-117-generic/aarch64, Python 3.12.3, systemd 255 (255.4-1ubuntu8.15), nftables v1.0.9 (Old Doc Yak #3). All eleven case groups and thirty-seven evidence-corruption controls passed. Installed site-packages module hashes match this source.

Configured management diagnostics rejected an own-policy management-port block without changing state/kernel policy. A first-match ordered allow remained allowed. Disposable external input chains at priorities -100 and 10 both blocked a real fresh TCP connect to the probe port and were diagnosed as blocked. An unsupported source-address condition remained risk. Each drop required the same live listener and success before/after removing only the fixture table; connection refusal was rejected. Foreign rules were identical before/after diagnosis and an admitted policy change. Both missing/null configuration trials retained pending journal/candidate rules immediately before SIGKILL, restored BASE on restart before API refusal, reached the bounded start limit, and recovered service after local configuration repair/reset/start. The old TLS confirmation returned 409 and a fresh connection committed. This checks loopback within the VM namespace, not external routes or WAN.

| Foreign chain priority | Observed plan ms | New TCP connect | Diagnostic |
|---|---:|---|---|
| -100 | 51.02 | blocked | blocked |
| 10 | 53.03 | blocked | blocked |

Each interval has raw monotonic endpoints and includes namespace/CLI process startup, TLS, kernel preflight and inventory. These are single observations for different fixture conditions, not isolated inspection cost or comparative performance. The unconfigured container benchmark has a different timing scope.

The malformed snapshot produced DEGRADED with unchanged rules/data. The legal pending ID `initial` survived sustained missing-key startup failure. The failed unit retained MainPID=0, Result=exit-code, NRestarts=6 for **2.21 s** without another restart. Its bounded current-boot receipt establishes rate-limit refusal; candidate rules and pending journal remained until local cause repair plus explicit reset/start restored the baseline. Stale requests did not overwrite a newer change. This is not independent rollback or arbitrary journal repair.

A separate Agent SIGKILL trial reached observed fresh TLS readiness in **1340.6 ms**, with baseline readback timestamped afterward. Orderly VM stop/start plus validation took **11.85 s** (pending) and **11.61 s** (committed), each one observation including probing/control overhead. These are not recovery upper bounds. The raw uptime field is kernel uptime, not Agent startup latency.

| Observation stage | Agent RSS MiB | Agent VmHWM MiB | Service cgroup MiB |
|---|---:|---:|---:|
| setup | 22.20 | 22.20 | 10.68 |
| management_diagnostics | 23.06 | 23.06 | 11.89 |
| dual_stack | 23.54 | 23.54 | 12.32 |
| poisoned_journal | 22.31 | 22.31 | 10.76 |
| restart_limit | 22.73 | 22.73 | 11.46 |
| crash | 22.80 | 22.80 | 11.46 |
| after_pending_boot | 22.74 | 22.74 | 11.88 |
| after_committed_boot | 22.20 | 22.20 | 11.24 |

The configured diagnostic sample belongs to its stable service invocation. Restart-limit memory is sampled after local recovery. All memory samples are joined to the appropriate boot; process/cgroup/VM memory scopes remain distinct. CPU/log saturation, large real-world ruleset performance, WAN/NAT/bridge/legacy firewall behavior, native segmentation faults, uninterruptible I/O and power loss were not tested. Historical failed/superseded attempts remain visible.

## Dual-stack observations

The installed dual-mode service used static IPv4/IPv6 veth peers. IPv6 connect returned errno 11 while repeated IPv4 confirmations remained AWAITING_CONFIRM with only ipv4 recorded. Core kernel-restoration completion was observed 47.44 ms after the common deadline; fresh TLS then succeeded in both families. This is one controlled observation, not a deadline/recovery upper bound.

A separate successful operation observed IPv4 partial confirmation in 4.63 ms and IPv6 final commit in 4.18 ms. These include fresh TLS and durable state writes but exclude client-process startup. The state transitions differ, so these are not a paired family performance comparison. Agent RSS/VmHWM and service-cgroup memory for that stable dual service are listed separately above.

A partial-confirmation SIGKILL restored the last dual commit with a newer generation; stale confirm/cancel/apply requests could not change a distinct successor. Both foreign marker tables were unchanged. Static neighbour discovery was observed after cache flush, and the temporary client namespace/veth were removed. This does not establish dual VM reboot, routed PMTU, SLAAC/RA filtering, WAN, native segmentation-fault, hung-I/O, early-boot or power-loss recovery.
