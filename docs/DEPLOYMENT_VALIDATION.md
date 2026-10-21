# Installed systemd service and VM restart validation

This suite runs the production service under actual systemd in a dedicated Colima Linux VM, outside containers. The service's firewall writes are confined to the disposable `rm_deployment` network namespace. It complements the portable macOS and containerized Linux suite; it does not turn macOS into a supported agent host.

## Run and audit

Use a previously provisioned, stopped, dedicated VM with no running containers or existing Rulemoor installation. The selected VM is restarted three times. Do not share the selected profile with another active task.

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

The configured [management diagnostic scenario](MANAGEMENT_PREFLIGHT.md) runs immediately after setup, before the existing recovery cases. It enables the production `--management-paths` argument using a fixture-only service drop-in, refuses an own-policy block, diagnoses real foreign input drops at priorities -100 and 10, preserves foreign rules and requires fresh TLS confirmation. Its TCP listener/probes are namespace-local. Each foreign-drop observation requires the same live listener and success → timeout → success after removing only the fixture table; refusal is not evidence of a drop. Missing/null management configuration is separately introduced while a change is pending, then MainPID is SIGKILLed: startup must restore baseline before refusing API admission. Configuration repair/reset/start must recover service. It removes the configuration override and disposable foreign table before the recovery cases. All fifteen groups are required.

1. **Installed unit:** actual systemd PID 1, installed package byte equality, exact production unit digest, sandbox/capability checks and TLS readiness.
2. **Configured management diagnostics:** production service with declared ports, rejected own-policy block, ordered allow, real TCP probes against earlier/later foreign drops, conservative unsupported-condition diagnosis, unchanged foreign rules and old/fresh TLS confirmation. The same group includes missing/null admission-configuration recovery through the installed entrypoint; its supported argument override is removed before the other recovery cases.
3. **Fresh dual-stack slice:** actual installed entrypoint over IPv4/IPv6 static veth peers; refused legacy adoption, second-family rejected-batch nonmutation, old/fresh transport checks, repeated IPv4 partial confirmation while fresh IPv6 is blocked, whole-policy timeout rollback, two-family commit, neighbour discovery, partial-confirmation SIGKILL recovery, immediate per-stale-request journal/kernel preservation, foreign-rule preservation and explicit client/veth cleanup. It restores the legacy fixture before the following VM reboot tests. See [dual-stack scope](DUAL_STACK.md).
4. **Malformed snapshot:** write a JSON list into the actual SQLite snapshot while stopped, start the installed unit and require DEGRADED, blocked mutation, unchanged kernel/data and stable invocation/restart count over a 2.2-second observation. Preserve private evidence, stop writers, then explicitly reprovision the disposable baseline and rotate credentials for subsequent cases. No production automatic repair is claimed.
5. **Persistent startup failure:** apply an unconfirmed candidate using the legal operation ID `initial`, withhold the TLS key and kill MainPID. The real installed ExecStart repeatedly exits before recovery and must hit the production start limit. A current-boot structured systemd journal receipt must identify the rate-limit refusal between this fault starting and the failed-state observation beginning; some versions retain `Result=exit-code` rather than `start-limit-hit`. Retain failed/stable unit properties, an unchanged pending journal and candidate kernel policy. Restoring the key alone must not bypass the rate limit. Repair plus explicit reset/start must restore the baseline; stale requests must not alter a newer pending or committed policy. This is not a segmentation-fault or uninterruptible-I/O test.
6. **Agent SIGKILL:** with an unconfirmed policy active, kill only MainPID; observe systemd's new invocation/PID and increased restart count, baseline readback and fresh TLS readiness. Submit a newer change, challenge it with old confirmation/cancel/apply requests while it is pending, then confirm and challenge again.
7. **Old executor:** a test-only drop-in temporarily enables the production held-executor hook. Observe its real process identity, remove the test override, kill MainPID and verify cgroup cleanup/recovery. A distinct newer policy must survive releasing the old hook and stale requests. This is explicitly fault injection, not an ordinary deployment setting.
8. **Pending boot preparation:** install an unconfirmed candidate, then stop the agent with a temporary SIGKILL/no-restart override. Verify its journal is still pending and the candidate is still in the kernel. After reboot, the namespace bootstrap reads a safe projection of the durable journal before starting the agent; it must still exactly match the stopped pending state. Remove the override before restarting the VM. This prevents a graceful shutdown rollback from masquerading as boot recovery.
9. **Pending VM boot:** orderly VM stop/start, changed kernel boot ID, namespace created with no owned table before the agent starts, enabled unit starts automatically, baseline reconstructed and generation advanced. Retain the journal before the agent starts, then the actual kernel/generation and rejected request paths while challenging a newer pending and committed policy with pre-boot requests.
10. **Committed VM boot:** a second orderly VM stop/start must recreate the confirmed policy and advance the generation. An old base is rejected. A subsequently installed foreign table is retained with DEGRADED status after service restart.
11. **Dual partial boot preparation:** explicitly fresh dual fixture, normal two-family committed baseline, different candidate confirmed only through IPv4, SIGKILL/no-restart service stop, unchanged pending journal and both candidate tables before shutdown.
12. **Dual pending VM boot:** third orderly stop/start, changed boot ID, both tables absent and unchanged pending journal read before automatically starting the installed dual Agent; both baseline tables and fresh IPv4/IPv6 TLS recover. Stale pre-boot requests cannot alter a distinct successor.
13. **Dual orphan executor:** installed production Controller/executor held before nft write outside the service cgroup; kill only its Agent, observe the executor alive and writer.lock held, then start the installed systemd Agent and require pidfd retirement/free writer ownership before a distinct dual successor. Release the retired intent and verify unchanged journal/tables for a finite observation.
14. **Dual management preflight:** configured two-family ports, IPv6 own-policy refusal despite IPv4 permission, ip6/inet external drops and unknown IPv6 address conditions, same-listener success/timeout/recovery, foreign-rule preservation, fresh dual confirmations and cancel/deadline/SIGKILL restoration despite a guard-blocked baseline. No configured-guard VM reboot is added.
15. **Cleanup:** disable/remove the service and fixture, remove namespace workers, credentials, private state, installed package and source snapshot; verify the VM root firewall is unchanged and stop the VM.
Nonzero commands, timeout, missing cases/stages, changed sources, unchanged boot identity, altered pre-agent journal, stale kernel output, nonfinite/inconsistent measurements, wrong process identity or cleanup failure cannot produce a passing report. Sixty-five deliberate evidence-corruption controls challenge the verifier. JSON and HTML are generated from the same observations and rechecked byte-for-byte by the auditor. Raw host logs and private operational receipts remain ignored/local; shared artifacts exclude credentials and confirmation challenges. Interrupted VM-manager/host failures can require manual recovery; stopping the driver forcibly is not a guaranteed cleanup path.

## Measurements and limits

The JSON retains raw kernel policies, generations, process/boot identities, restart counts, daemon RSS/VmHWM and systemd cgroup memory. It also records one Agent-SIGKILL-to-observed-TLS-readiness interval and one host-observed stop/start/validation interval for each VM case. Raw monotonic nanosecond endpoints allow recomputation of those intervals. TLS readiness is timestamped immediately after the successful probe, before the separate baseline readback; the latter endpoint is also retained. These include probing, SSH, VM control and assertion overhead; they are neither exact service-only boot latency nor recovery-time upper bounds. Memory measurements are observations, not continuous peak sampling of the entire deployment. The diagnostic and repaired-service samples must match the setup boot, and the diagnostic sample must match its observed invocation. Each sample retains stable MainPID/start-time/boot identity, systemd invocation, executable entrypoint, cgroup and matching namespace identity. If the process changes during sampling, the sample fails. The committed-boot sample is taken before the separate foreign-policy restart. Agent VmHWM excludes nft children, clients and VM memory; cgroup memory has a different scope and includes service children and charged memory. VM RAM is not reported as daemon RSS.

These measurements come from VM system services (configured 4 vCPU / 6 GiB), separate from the 2-vCPU / 768-MiB container operation measurements in `MEASUREMENTS.md`. Python/nftables/systemd versions are retained separately. Do not interpret differences between those environments or runs as performance improvements.

**Power-loss recovery is not tested.** VM stop/start uses orderly shutdown, not abrupt power removal or storage fault injection. Systemd restart limits, boot dependencies and storage availability can delay/prevent recovery. There is no running rollback timer while the agent is stopped. The owned rules can be absent before service startup, so this is not fail-closed early boot or uninterrupted management access. Other hosts, architectures, firewall managers and storage stacks require their own validation.

[Evidence review and corrections](DEPLOYMENT_REVIEW.md) · [Retained JSON](../reviews/deployment/deployment.json) · [HTML report](../reviews/deployment/report.html) · [Attempt history](../reviews/deployment/attempts.json)





## Retained observations

Run `c6c726cffd12db8e`, source `5d2899bf453b3f6491afb0f7e9ebf52f70cf339035e205705985eb457af973ac`. Kernel 6.8.0-117-generic/aarch64, Python 3.12.3, systemd 255 (255.4-1ubuntu8.15), nftables v1.0.9 (Old Doc Yak #3). All fifteen case groups and sixty-five evidence-corruption controls passed. Installed site-packages module hashes match this source. The first helper-import attempt failed and was cleaned/stopped; it remains in attempt history.

Configured management admission/foreign-rule diagnosis retained same-listener success → timeout → success after removing only fixture rules. Unknown conditions remained risk, old TLS confirmation was refused, a fresh connection committed, and foreign rules remained unchanged. These observations remain namespace-local.

| Foreign priority | Observed plan ms |
|---|---:|
| -100 | 58.95 |
| 10 | 64.70 |

Plan observations include CLI process/namespace startup, TLS and checks. They are not isolated diagnostic CPU time or a paired comparison with the unconfigured legacy container benchmark.

Missing-key startup failure reached the real start limit and remained stopped for 2.21 s before local cause repair/reset/start. A separate legacy Agent SIGKILL trial reached observed fresh TLS in 1295.4 ms, with baseline readback afterward. Neither is a recovery upper bound.

| Orderly VM stop/start + validation | Observed seconds |
|---|---:|
| Legacy IPv4 pending | 13.20 |
| Legacy IPv4 committed | 12.96 |
| Dual partial confirmation | 12.74 |

Each is one host-monotonic interval including Colima, SSH, namespace setup, probing and assertions. No power removal is performed.

The original dual confirmation case still observes IPv6 timeout errno 11 with repeated IPv4 partial confirmation, followed by both-policy timeout restoration. Its separate IPv4 partial / IPv6 final confirmation round trips were 5.15 / 4.69 ms; these are different state transitions, not a family speed comparison.

The new dual reboot retained AWAITING_CONFIRM with only ipv4 recorded before shutdown and before new-boot Agent startup. Both tables were absent before startup. Recovery restored the last normal commit and advanced generation 2 → 3; fresh IPv4/IPv6 TLS agreed. Immediate stale-request readbacks preserved the later dual successor.

The held executor survived its temporary Agent outside rulemoor.service with writer.lock held. The installed Agent retired its recorded identity and freed writer ownership before a different successor committed. Readbacks before releasing the old intent and after waiting 2.105 s matched for both kernel tables and the journal; this was not continuous observation. The executor was already retired before release; this is not a claim that a live stale writer safely resumed.

The configured dual guard rejected an IPv6 candidate denial while IPv4 was allowed. External IPv6-only drops remained blocked and an unsupported source-address condition remained risk while IPv4 had no observed conflict. Same-listener probes timed out only for IPv6 and succeeded again after removing fixture rules. Foreign table readbacks matched immediately before/after plan, apply, partial confirmation and cancel for both known and uncertain cases. Receipt boot/op/generation and policies match the bound scenario chain; these are endpoints, not continuous monitoring. Old TLS confirmations were refused; fresh IPv4 partial plus IPv6 final confirmation committed. Cancel/deadline/SIGKILL restart restored both guard-blocked baseline policies.

| Configured dual foreign table | Priority | Observed plan ms |
|---|---:|---:|
| ip6 | -100 | 55.89 |
| ip6 | 10 | 85.08 |
| inet | -100 | 73.63 |

Each plan value is one endpoint observation including CLI/namespace/TLS overhead, not isolated evaluator cost or a paired performance comparison. The configured-guard scenario does not reboot the VM.

| Stage | Agent RSS MiB | Agent VmHWM MiB | Service cgroup MiB |
|---|---:|---:|---:|
| setup | 22.21 | 22.21 | 10.69 |
| management_diagnostics | 23.06 | 23.06 | 11.88 |
| dual_stack | 23.55 | 23.55 | 12.28 |
| poisoned_journal | 22.31 | 22.31 | 10.76 |
| restart_limit | 22.89 | 22.89 | 11.60 |
| crash | 22.85 | 22.85 | 11.55 |
| after_pending_boot | 22.84 | 22.84 | 11.98 |
| after_committed_boot | 22.21 | 22.21 | 11.04 |
| after_dual_boot | 22.97 | 22.97 | 12.12 |
| dual_held_executor | 23.02 | 23.02 | 11.68 |
| dual_management_diagnostics | 22.35 | 22.35 | 10.88 |

Samples retain stable service PID/start/boot/invocation and cgroup/namespace association. New dual recovery samples belong to the third boot, not the setup boot. Agent VmHWM excludes children/client/VM; cgroup accounting differs from Agent RSS and total VM RAM. Run-to-run differences are not optimization claims.

[Dual boot/orphan method and boundaries](DUAL_RECOVERY.md). Committed-only dual VM boot, other executor/kernel boundaries, routed PMTU, SLAAC/RA policy, general firewall compatibility, sudden power loss, uninterruptible I/O, fail-closed early boot and uninterrupted connections remain unestablished.
