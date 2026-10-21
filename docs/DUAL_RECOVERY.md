# Dual-stack VM boot and delayed-executor recovery

This extends the installed-service validation with an actual **third orderly VM stop/start** and a deliberately orphaned dual executor. It uses the production wheel, Controller, nft backend/executor and systemd Agent in a disposable network namespace. It does not simulate the production state machine in a separate implementation.

## Partial confirmation across a real VM restart

The fixture creates a fresh dual installation; it does not migrate or adopt a live deployment. It first changes both policies and confirms over fresh IPv4 and IPv6 TLS, establishing a normal committed baseline. A different two-family candidate is then applied, but only IPv4 confirms.

Before VM shutdown, a temporary test-only unit override uses SIGKILL and disables restart. The fixture requires the journal to remain AWAITING_CONFIRM with only IPv4 confirmed and both candidate policies still in the kernel after the Agent has stopped. The override is removed before the orderly VM stop/start.

On the new boot, the namespace dependency creates the static IPv4/IPv6 veth peers before the production Agent starts. It records both owned tables as absent and reads a safe projection of the persistent journal. That projection must exactly equal the pre-shutdown pending journal. A rollback completed before shutdown cannot satisfy this check.

The automatically started, installed dual-mode Agent must restore **both** policies from the last normal commit, retain a rolled-back outcome rather than promote the partial receipt, use the new boot ID and advance generation. Fresh certificate-verified IPv4 and IPv6 TLS requests must return the restored state. A distinct successor is then challenged with pre-boot confirm/cancel/apply requests; journal and both kernel tables are read immediately before and after each rejection, before legitimate dual confirmation commits that successor.

## Orphan executor that systemd did not kill

A normal systemd cgroup restart can kill all service children before Controller fencing runs. That is useful operational protection, but does not independently exercise pidfd retirement. This fixture deliberately creates a harder case:

1. Stop the committed dual Agent. Run the installed production Controller/backend outside the service cgroup, using the supported internal executor-held fault hook.
2. Observe the real executor PID/start/boot identity, APPLYING journal, unchanged baseline kernel policies and its cgroup outside rulemoor.service. Kill only the temporary Agent; require the executor to remain alive and hold the inherited writer lock.
3. Start the ordinary installed systemd Agent. Its production startup must retire the identified orphan before taking writer ownership and completing rollback. Require the old identity to be gone, the lock free and both known baseline policies restored.
4. Apply and freshly confirm a successor whose IPv4 **and** IPv6 policies differ from both the old candidate and baseline. Reject the old cancel/apply operations while the successor is pending and committed, checking journal and kernel immediately around each request.
5. Release the old fault-hook intent only after that successor commits. Require the old executor identity to remain retired and both successor tables/journal unchanged in readbacks before release and after a wait exceeding two seconds.

The test proves retirement before successor admission and preservation after a late release attempt. It does not claim an old executor remains alive, resumes and is magically prevented from writing; the safety mechanism is to retire it first. The forced orphan is test-only process placement, not the default systemd deployment behavior. The normal production unit retains KillMode=control-group and its existing sandbox settings.

## Formal tests and report checks

Portable tests call the formal Controller with real SQLite state: either first-confirmed family must recover the last normal dual commit after a changed boot; failed executor retirement must enter DEGRADED and reject successor admission. A production mutation that removes retirement must fail an assertion. Memory-backend tests are not real process/kernel evidence; the separate VM fixture supplies that evidence.

Report checks bind pre-stop, pre-Agent and recovered observations to the appropriate boot, operation, generation and distinct per-family policies. Required corruption controls challenge pre-Agent pending state, a missing restored family/TLS result, unchanged boot, an orphan already dead before startup, an unretired executor, wrong post-release rules and missing observation clocks. Stable Agent RSS/VmHWM and service-cgroup memory are reported separately from VM RAM. VM stop/start intervals include host control, namespace setup, TLS probes and assertions; they are single observations, not recovery-time upper bounds.

Shared JSON/HTML excludes credentials, private confirmation challenges and state databases. The extra client namespace and all known test processes must be removed; the VM root firewall must remain unchanged and the VM must end stopped. Failed or superseded attempts are retained as such rather than counted as passing evidence.

## Boundaries

The reboot is **orderly VM stop/start**, not sudden power loss. It does not validate storage corruption, lost fsync writes, native segmentation faults, hung kernel I/O or fail-closed early boot. There is still no independent rollback timer while the Agent is stopped. Routed PMTU, SLAAC/RA filtering, general firewall compatibility and uninterrupted connections remain outside this static-peer experiment. ICMPv6 policy remains the documented permissive TCP-MVP choice.

The new actual dual boot trial covers a partially confirmed pending change. A separate dual-mode committed-only VM boot is not exercised; the existing committed-only VM boot remains legacy IPv4. The orphan test injects a hold before the old executor's nft write, not every possible kernel/Netlink boundary or uninterruptible process state. The readbacks bracket the wait; they are not continuous observation and cannot rule out arbitrary transient changes between reads. A finite post-release observation does not establish protection against arbitrary privileged writers forever. The distinct fixture policies use different redundant TCP drop-rule markers under default-drop; exact canonical readback proves both rule sets are preserved, while the fresh TLS checks cover the management ports. This is not a broad data-plane equivalence test.

[Method and latest measurements](DEPLOYMENT_VALIDATION.md) · [JSON](../reviews/deployment/deployment.json) · [HTML](../reviews/deployment/report.html)

Retained executable source `a0c093c5ee46f8a93d23f7ffb4bcb280c2a0cdc47de8803b6ba5cb9bc77f76ac`; native/container run `ef8a435b0ccead85` (109 tests per platform, 32 production mutations); actual-systemd VM run `9d88cdff84bdc2e6` (15 groups, 57 evidence controls). VM final state: Stopped. Power-loss tested: false.

[Independent follow-up review and corrections](DUAL_RECOVERY_REVIEW.md).
