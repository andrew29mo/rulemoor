# Boot Guard audit — 2026-10-21

The audit challenges the installed-service contract for the isolated static-veth
MVP. Passing unit tests alone does not establish a safe deployment. Current
measurements and source identity are in [the retained run](../reviews/guard/README.md).

## Fixed findings

1. **Receipt failure could prevent DOWN.** Previously, `close_locked()` wrote
   CLOSING before attempting the interface command. ENOSPC/EIO could skip DOWN;
   an OPEN receipt failure after activation could therefore leave the link UP,
   including when ExecStopPost encountered the same error. Closing now proceeds
   independently of receipt writes. Write failure still fails the command, and
   an actual interface failure is not replaced by a secondary FAULTED-write error.
   Portable tests inject EIO/ENOSPC/EROFS. A real installed-service test creates
   an EISDIR destination error after actual UP and requires both open cleanup
   and ExecStopPost DOWN commands; another tests normal stop with the fault.
   EISDIR is not evidence of real disk exhaustion or power-loss durability.
2. **Consistent DEGRADED receipts could pass the report verifier.** Equality of
   journal/receipt/TLS phase was insufficient. OPEN evidence must now have a
   terminal COMMITTED or ROLLED_BACK phase and a monotonic clock.
3. **Essential provenance and memory evidence was optional to the verifier.**
   Removing the base Agent service evidence, deleting Agent memory or changing
   held-process RSS scope to whole-VM memory could previously retain report PASS.
   The verifier now requires installed-module and base-unit hashes, relevant unit
   properties, sampled process identity, memory boundaries and finite timings.
   Corrupted-report controls cover each of these failure modes. These controls
   challenge report consistency; they are not independent hardware observations.

The added production mutation initially encountered a test-import error under
single-test execution. That error was not counted as catching a regression.
The import now supports both discovery and a fully qualified single test; the
retained mutation receipt requires assertion failure, not syntax/import failure.

## Boundaries retained

The privileged `ExecStartPre=+` anchor step is a trusted root bootstrap dependency.
It reads PID 1's namespace identity and writes a private boot-bound anchor; it
does not load policy or enable a link. The main/stop helpers retain the reduced
capability set. This does not sandbox arbitrary root actors or automatically
exclude other network managers; exclusive activation is a deployment precondition.

Both families require real permitted echo, denied connect probes with live
listeners, and fresh TLS access. Pending reboot evidence preserves the journal
before service startup on a new boot and independently reads both tables absent
and the interface DOWN. This excludes pre-shutdown rollback as the explanation
for the tested recovery. Delayed executor evidence retires an identified orphan
before admitting its successor; it does not cover every kernel interruption.

The OPEN interval ends at the observation before the final receipt write/fsync,
not after durable receipt completion. Guard RSS is a held-point process sample;
Agent RSS, service cgroup memory and VM memory are distinct scopes. No recovery
SLA or aggregate speedup follows from these observations.

Whole-host early-boot zero-gap, physical NIC/network-manager integration and
sudden power-loss recovery remain untested. If DOWN itself fails, local rescue
is still required. If receipt storage fails, cached OPEN is not authoritative.
