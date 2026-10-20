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

The runner makes an immutable executable snapshot, builds a wheel, installs it in `/opt/rulemoor/venv`, and compares installed module bytes with that snapshot. It installs the exact `deploy/rulemoor.service`, verifies it with `systemd-analyze`, and checks the running unit's restart, cgroup, namespace, capability and sandbox properties. A fixture-only dependency creates the namespace after each boot; a drop-in selects it and enables memory accounting. The production bind address remains loopback, so these tests establish fresh TLS access inside the namespace, not external network routing or WAN reachability.

## Cases and distinguishing observations

1. **Installed unit:** actual systemd PID 1, installed package byte equality, exact production unit digest, sandbox/capability checks and TLS readiness.
2. **Agent SIGKILL:** with an unconfirmed policy active, kill only MainPID; observe systemd's new invocation/PID and increased restart count, baseline readback and fresh TLS readiness. Submit a newer change, challenge it with old confirmation/cancel/apply requests while it is pending, then confirm and challenge again.
3. **Old executor:** a test-only drop-in temporarily enables the production held-executor hook. Observe its real process identity, remove the test override, kill MainPID and verify cgroup cleanup/recovery. A distinct newer policy must survive releasing the old hook and stale requests. This is explicitly fault injection, not an ordinary deployment setting.
4. **Pending boot preparation:** install an unconfirmed candidate, then stop the agent with a temporary SIGKILL/no-restart override. Verify its journal is still pending and the candidate is still in the kernel. Remove the override before restarting the VM. This prevents a graceful shutdown rollback from masquerading as boot recovery.
5. **Pending VM boot:** orderly VM stop/start, changed kernel boot ID, namespace created with no owned table before the agent starts, enabled unit starts automatically, baseline reconstructed and generation advanced. Challenge a newer pending and committed policy with pre-boot requests.
6. **Committed VM boot:** a second orderly VM stop/start must recreate the confirmed policy and advance the generation. An old base is rejected. A subsequently installed foreign table is retained with DEGRADED status after service restart.
7. **Cleanup:** disable/remove the service and fixture, remove namespace workers, credentials, private state, installed package and source snapshot; verify the VM root firewall is unchanged and stop the VM.

Nonzero commands, timeout, missing cases, changed sources, unchanged boot identity, stale kernel output or cleanup failure cannot produce a passing report. Six deliberate evidence-corruption controls challenge the verifier. JSON and HTML are generated from the same observations and rechecked byte-for-byte by the auditor. Raw host logs and private operational receipts remain ignored/local; shared artifacts exclude credentials and confirmation challenges. Interrupted VM-manager/host failures can require manual recovery; stopping the driver forcibly is not a guaranteed cleanup path.

## Measurements and limits

The JSON retains raw kernel policies, generations, process/boot identities, restart counts, daemon RSS/VmHWM and systemd cgroup memory. It also records one Agent-SIGKILL-to-observed-TLS-readiness interval and one host-observed stop/start/validation interval for each VM case. These include probing, SSH, VM control and assertion overhead; they are neither exact service-only boot latency nor recovery-time upper bounds. Memory measurements are observations, not continuous peak sampling of the entire deployment. Agent VmHWM excludes nft children, clients and VM memory; cgroup memory has a different scope and includes service children and charged memory. VM RAM is not reported as daemon RSS.

These measurements come from VM system services (configured 4 vCPU / 6 GiB), separate from the 2-vCPU / 768-MiB container operation measurements in `MEASUREMENTS.md`. Python/nftables/systemd versions are retained separately. Do not interpret differences between those environments or runs as performance improvements.

**Power-loss recovery is not tested.** VM stop/start uses orderly shutdown, not abrupt power removal or storage fault injection. Systemd restart limits, boot dependencies and storage availability can delay/prevent recovery. There is no running rollback timer while the agent is stopped. The owned rules can be absent before service startup, so this is not fail-closed early boot or uninterrupted management access. Other hosts, architectures, firewall managers and storage stacks require their own validation.

[Retained JSON](../reviews/deployment/deployment.json) · [HTML report](../reviews/deployment/report.html) · [Attempt history](../reviews/deployment/attempts.json)

## Retained observations

Run `dfad2049d204fa28`, source `30c1f7696bde723df46409031d531baf3ebd50aa1f51c36129497dbf71ee6ad4`. Kernel 6.8.0-117-generic/aarch64, Python 3.12.3, systemd 255 (255.4-1ubuntu8.15), nftables v1.0.9 (Old Doc Yak #3). All seven case groups and six evidence-corruption controls passed.

One Agent SIGKILL trial reached observed baseline/TLS readiness in **1383.8 ms**. The two host-observed orderly VM stop/start plus validation intervals were **12.95 s** (pending) and **13.22 s** (committed). These are single observations including the control/probe overhead described above. The raw `vm_uptime_after_validation_seconds` value is the VM’s kernel uptime after the case, not Agent startup latency.

| Observation stage | Agent RSS MiB | Agent VmHWM MiB | Service cgroup MiB |
|---|---:|---:|---:|
| setup | 22.15 | 22.15 | 10.64 |
| crash | 22.78 | 22.78 | 11.50 |
| after_pending_boot | 22.74 | 22.74 | 13.44 |
| after_committed_boot | 22.28 | 22.28 | 10.79 |

Cgroup charge accounting and process RSS have different treatment of shared/cache pages; these columns are not additive or interchangeable. Neither is total VM memory. Earlier failed/superseded attempts remain in the attempt history.
