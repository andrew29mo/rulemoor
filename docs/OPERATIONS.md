# Installation and operation

## Deployment prerequisites

Start in a disposable Linux VM or namespace. Keep console access independent of Rulemoor. The initial backend was exercised on Linux 6.8/aarch64 and nftables 1.0.6; other versions require the real-kernel suite, not just portable tests. Use one controller and do not let another manager edit `ip rulemoor`.

Install Python 3.12 and nftables using the target system's package manager. To install command entry points, create `/opt/rulemoor/venv` and run its `pip install /path/to/checkout`. Runtime Python dependencies are standard-library only; building uses setuptools. The example unit references these installed entry points. The repository also runs directly with `python -m rulemoor.service` and `python -m rulemoor.cli`.

Provision `/etc/rulemoor/server.pem`, `server.key` and `token` out of band. Use a certificate whose SAN covers the actual management address, with a trusted CA or an explicitly pinned self-signed certificate. Generate at least 32 random bytes for the bearer token (for example `openssl rand -hex 32`). Keep key/token files mode 0600; never put actual credentials in Git, shell arguments, HTML reports or issue attachments. Install a copy of the CA and token securely on the operator machine.

Create `/var/lib/rulemoor` owned by the service user with mode 0700. First initialization refuses both an existing journal and an existing table. Run initialization once, with a reviewed baseline. The default-accept example is a test/example policy, not a recommended production firewall. Existing unrelated firewall rules remain in place and can independently block access.

The supplied `deploy/rulemoor.service` binds loopback by default. Review its management bind address and certificate before enabling remote operation. Copy it into the target's service-manager directory only after reviewing paths and permissions. The unit has been exercised under actual systemd, with a test-only network-namespace dependency/drop-in, in the retained isolated Linux VM deployment suite. This is not validation of every host’s boot/network/firewall ordering. It restarts failed processes, clears fault-test hooks, limits privileges to the backend requirements and uses a private state directory. The process lock is advisory, not a boundary against root.

## Normal change procedure

1. `status`: verify a terminal state and the expected base generation.
2. `plan POLICY`: inspect differences and run kernel preflight without changing rules.
3. `apply POLICY --op UNIQUE_ID --generation BASE --window SECONDS`: accepted windows are 1–300 seconds.
4. Reconnect using the intended management path, then `confirm --op ID --generation NEW`.
5. If uncertain, do not confirm. Inspect status after the deadline or explicitly `cancel` the matching pending operation.

The service allows one unfinished change. Each accepted connection has a 5-second absolute lifetime; reconnect rather than assuming an indefinitely persistent keepalive. If a long operation outlives its response connection, inspect status before retrying. Stale bases, stale challenges, old connections and conflicting ID reuse receive HTTP 409. The ID `initial` is allowed for a normal change; initialization is distinguished by journal structure. A retry with the same retained apply ID and identical payload returns its existing receipt rather than reapplying. A lost confirm/cancel response requires `status`; an already terminal operation is not confirmed/cancelled a second time.

## Restart and shutdown

Process SIGTERM/SIGINT stops acceptance and attempts rollback of a pending change. SIGKILL skips graceful cleanup; on the next start, the controller fences any identified orphan writer and reconciles the journal with actual rules. Known unfinished candidates are restored to their baseline. Known committed policy remains committed. A post-commit checkpoint error is a maintenance warning in status, not a reversal of the durable confirmation. A generation increase prevents old pending operations from being confirmed after recovery.

A stopped process has no active deadline timer. Service-manager restart speed and availability matter; there is no guarantee of a rollback at the deadline while the service is down. The deployment suite verifies automatic systemd process restart and two orderly Linux VM stop/start cycles. Actual power loss, arbitrary filesystem/storage failures and other hosts’ boot ordering remain untested. See [deployment validation](DEPLOYMENT_VALIDATION.md).

## Persistent startup failure and rate limiting

The supplied unit uses `Restart=on-failure`, `RestartSec=1`, `StartLimitIntervalSec=60` and `StartLimitBurst=5`. This bounds starts within a rate-limit window; it is not automatic policy repair. A process that repeatedly exits can reach the start limit with no running agent. Some systemd versions retain `Result=exit-code`; inspect the actual rate-limit journal message as well as status and restart count. A still-installed pending candidate can remain in the kernel, and its deadline cannot cause rollback while the agent is stopped.

Use independent console access to inspect service status and private logs. Repair the underlying startup dependency first, then explicitly reset the service's failed state and start it. Check authenticated status, the expected baseline/committed kernel policy and a fresh management connection separately. Merely restoring a missing file, observing `ActiveState=active`, or resetting the counter does not establish recovery. Repeatedly resetting the limit without fixing the cause defeats its protection.

The isolated deployment suite makes the actual installed agent fail repeatedly by withholding its TLS private key after an unconfirmed change. It checks the failed unit, unchanged pending journal and candidate rules before repairing the dependency and resetting the limit. This is a reproducible nonzero startup failure, not a native segmentation-fault or blocked-kernel-I/O test. It does not measure host CPU/log saturation or prove recovery from every program defect.

## DEGRADED and local recovery

`DEGRADED` means no further automatic change is allowed. Record `status`, copy the private state directory and inspect `nft -j -s list table ip rulemoor` locally. Preserve journal files, `rescue.json` and executor identity files as sensitive operational evidence. Never delete a writer lock to force takeover; an inherited descriptor can remain active after its parent dies.

The snapshot reader bounds stored JSON to 64 KiB and checks its schema, policies, generation, finite clocks, phase requirements and unfinished-transaction baseline/current equality before process fencing or kernel mutation. Missing, malformed, oversized or unusable snapshot data becomes an in-memory DEGRADED diagnostic and remains preserved on disk; it is not replaced with a guessed good policy. This is bounded validation of known invalid-state cases, not recovery of arbitrary corrupted storage. An active diagnostic process is not a healthy change controller.

Malformed or oversized executor identity data also produces DEGRADED and blocks changes; the service does not guess which PID to kill. For detected foreign policy, resolve ownership and policy deliberately using console access. For an unreadable journal or interrupted initial provisioning, do not infer a baseline from whatever happens to be installed. The MVP has no force-adopt or remote force-reset endpoint. Reprovisioning is a local administrative procedure: retire the service and any executor, retain forensic state, establish a reviewed known policy, and rotate credentials before creating a fresh installation. Avoid temporary removal of access controls on a live machine. Automated adoption/migration is outside this MVP.

The 4 MiB state-directory budget is an admission guard, not a disk quota or promise of continued disk availability. The 256 KiB reserve improves rollback opportunity after disk exhaustion but cannot guarantee recovery from arbitrary storage failures. Successful rule readback and successful management reconnection are separate evidence.

## Kernel rules after a new boot

Kernel nftables state is volatile. On a changed boot ID, after obtaining writer ownership, the controller recreates an absent owned table using the durable current policy for a terminal operation, or the baseline for an unfinished operation. Intent is committed before creation; readback is required before becoming ready. Pending changes are rolled back, never resumed. The boot ID is updated and the generation advances, including for a previously committed policy, to reject pre-boot base generations.

This exception does not apply to an absent table within the same boot, a preexisting foreign table, interrupted initial provisioning, unreadable journals or a prior DEGRADED state. These still block writes and require operator recovery. Do not configure another boot-time firewall loader to race with Rulemoor. The service starts after `network.target`; there can be an interval without its owned rules before startup. It is not a guarantee of fail-closed early boot, uninterrupted access, or a substitute for console recovery.
