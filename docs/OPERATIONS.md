# Installation and operation

## Deployment prerequisites

Start in a disposable Linux VM or namespace. Keep console access independent of Rulemoor. The initial backend was exercised on Linux 6.8/aarch64 and nftables 1.0.6; other versions require the real-kernel suite, not just portable tests. Use one controller and do not let another manager edit `ip rulemoor`.

Install Python 3.12 and nftables using the target system's package manager. To install command entry points, create `/opt/rulemoor/venv` and run its `pip install /path/to/checkout`. Runtime Python dependencies are standard-library only; building uses setuptools. The example unit references these installed entry points. The repository also runs directly with `python -m rulemoor.service` and `python -m rulemoor.cli`.

Provision `/etc/rulemoor/server.pem`, `server.key` and `token` out of band. Use a certificate whose SAN covers the actual management address, with a trusted CA or an explicitly pinned self-signed certificate. Generate at least 32 random bytes for the bearer token (for example `openssl rand -hex 32`). Keep key/token files mode 0600; never put actual credentials in Git, shell arguments, HTML reports or issue attachments. Install a copy of the CA and token securely on the operator machine.

Create `/var/lib/rulemoor` owned by the service user with mode 0700. First initialization refuses both an existing journal and an existing table. Run initialization once, with a reviewed baseline. The default-accept example is a test/example policy, not a recommended production firewall. Existing unrelated firewall rules remain in place and can independently block access.

The supplied `deploy/rulemoor.service` binds loopback by default. Review its management bind address and certificate before enabling remote operation. Copy it into the target's service-manager directory only after reviewing paths and permissions. The unit is an example; it has not been boot-tested under systemd. It restarts failed processes, clears fault-test hooks, limits privileges to the backend requirements and uses a private state directory. The process lock is advisory, not a boundary against root.

## Normal change procedure

1. `status`: verify a terminal state and the expected base generation.
2. `plan POLICY`: inspect differences and run kernel preflight without changing rules.
3. `apply POLICY --op UNIQUE_ID --generation BASE --window SECONDS`: accepted windows are 1–300 seconds.
4. Reconnect using the intended management path, then `confirm --op ID --generation NEW`.
5. If uncertain, do not confirm. Inspect status after the deadline or explicitly `cancel` the matching pending operation.

The service allows one unfinished change. Stale bases, stale challenges, old connections and conflicting ID reuse receive HTTP 409. A retry with the same retained apply ID and identical payload returns its existing receipt rather than reapplying. A lost confirm/cancel response requires `status`; an already terminal operation is not confirmed/cancelled a second time.

## Restart and shutdown

Process SIGTERM/SIGINT stops acceptance and attempts rollback of a pending change. SIGKILL skips graceful cleanup; on the next start, the controller fences any identified orphan writer and reconciles the journal with actual rules. Known unfinished candidates are restored to their baseline. Known committed policy remains committed. A generation increase prevents old pending operations from being confirmed after recovery.

A stopped process has no active deadline timer. Service-manager restart speed and availability matter; there is no guarantee of a rollback at the deadline while the service is down. Host reboot, disk power loss and service-manager integration are not covered by the retained results.

## DEGRADED and local recovery

`DEGRADED` means no further automatic change is allowed. Record `status`, copy the private state directory and inspect `nft -j -s list table ip rulemoor` locally. Preserve journal files, `rescue.json` and executor identity files as sensitive operational evidence. Never delete a writer lock to force takeover; an inherited descriptor can remain active after its parent dies.

For detected foreign policy, resolve ownership and policy deliberately using console access. For an unreadable journal or interrupted initial provisioning, do not infer a baseline from whatever happens to be installed. The MVP has no force-adopt or remote force-reset endpoint. Reprovisioning is a local administrative procedure: retire the service and any executor, retain forensic state, establish a reviewed known policy, and rotate credentials before creating a fresh installation. Avoid temporary removal of access controls on a live machine. Automated adoption/migration is outside this MVP.

The 4 MiB state-directory budget is an admission guard, not a disk quota or promise of continued disk availability. The 256 KiB reserve improves rollback opportunity after disk exhaustion but cannot guarantee recovery from arbitrary storage failures. Successful rule readback and successful management reconnection are separate evidence.
