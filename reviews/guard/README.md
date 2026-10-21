# Installed Boot Guard MVP evidence — 2026-10-21

Run `fcafb99bc50a8cb9`; executable source fingerprint
`369d57c25b23ad35b696f4e9f32437896c66dfaba6e49a989fa633faf9fddee0`.

**132 native macOS tests and 132 Linux portable tests passed**, zero failures/errors/skips. Executable manifests and exact test IDs match. The [production mutation suite](mutations.json) caught all 33 injected regressions by assertion: one new Boot Guard receipt-failure regression and 32 existing core/diagnostics/service controls. Separately, all 12 real VM phases passed, with 37 corrupted-report controls rejected. The fixtures installed the production wheel, exact base Guard unit and opt-in Agent dependency, with namespace/memory accounting overrides. See the [audit findings and fixes](../../docs/BOOT_GUARD_AUDIT.md).

[JSON](guard.json) · [HTML](report.html) · [native receipt](native-unit.json) · [development attempt ledger](attempts.json) · [design and reproduction](../../docs/BOOT_GUARD.md)

## Measurements

All are single observations in the same Colima Linux VM. These different recovery contexts are not comparable benchmark modes; no aggregate speedup or recovery bound is claimed.

| Observed scenario | Guard open path (ms) |
| --- | ---: |
| Initial load | 12.850 |
| Recovery after rejected write | 41.142 |
| Agent TLS key absent | 16.619 |
| Reopen after crash/close/receipt faults | 16.110 |
| Orphan retirement/recovery | 30.642 |
| Partially confirmed boot | 63.600 |
| Committed boot | 54.793 |

The internal interval starts inside Guard.open and ends at the monotonic observation **before** writing the final OPEN receipt. It includes address preparation, recovery, SQLite, nft and link operations/readbacks. It excludes startup/imports/profile loading, root setup, full systemd startup and the final OPEN receipt write/fsync. It is not durable receipt completion latency. Failed attempts and intermediate state changes are not hidden by these success-path intervals.

| Memory sample | RSS bytes | VmHWM bytes |
| --- | ---: | ---: |
| Guard held before-up | 18685952 | 18685952 |
| Guard held after-up | 18706432 | 18706432 |
| Agent initial | 23318528 | 23318528 |
| Agent after partial boot | 23248896 | 23248896 |
| Agent after committed boot | 23339008 | 23339008 |

Guard samples are the actual installed process held in its ip subprocess call, excluding children; VmHWM is observed up to that point, not a normal entire-run peak. Agent samples are running daemon process RSS/VmHWM; its cgroup memory_current is separately retained in JSON. At the held points, Guard cgroup MemoryPeak was before-up 10170368 bytes, after-up 10072064 bytes. Those SIGKILL records retain the same cgroup peaks after cleanup; the separate receipt-failure unit records report `[not set]`, not zero. These cgroup peaks are observed only up to the held point and use a different accounting scope from process RSS; they are not a normal entire-run peak or a memory saving comparison. These are VM process measurements, not native macOS or whole-VM memory.

Host stop/start plus control/verification/preparation intervals: partial boot 14.042 s; committed boot 12.981 s. The partial interval also includes preparation/commit of the next scenario. These are not management-access recovery times or SLAs.

## Observed correctness boundaries

* Production executor write rejection produces DEGRADED and DOWN; recovery follows explicit local fixture repair. No automatic untrusted-journal repair is claimed.
* Both SIGKILL hold points run the installed Guard with the same invocation/process identity; the subprocess is retired and actual close reads DOWN. An injected close-command failure leaves UP/FAULTED until separately observed manual rescue. PASS means these expected outcomes, not that every fault closes the link.
* A real EISDIR receipt destination error after UP still produces DOWN in open cleanup and formal ExecStopPost; normal stop with the same receipt fault also closes the link and fails the unit. Portable tests inject EIO/ENOSPC/EROFS at the writer boundary; real disk exhaustion and power loss were not tested.
* A subscription-ready route-netlink observer records no link events during the tested Agent restart. This is one finite observation window, not whole-boot link/packet coverage.
* Both families have actual external-peer allowed echo, blocked connect-stage probes with live listeners, and new certified TLS access. An echo timeout is not accepted as firewall blocking.
* Pre-guard observations independently read both owned tables absent and the unchanged pending/committed journal; only then does formal recovery install both correct policies and open the link. Orderly shutdown rollback cannot explain the pending recovery result.
* All fixture units, source snapshot, credentials/state and namespaces were removed; root VM firewall digest was unchanged; final VM state is Stopped.

The [ledger](attempts.json) preserves four failed development runs and their source fingerprints, followed by successful snapshots and the audit reruns. The first audit VM run passed, but its separate new mutation had an import error and was not counted as regression detection; the final source fixes that import and reruns both platforms, the VM matrix and all mutations. Failures exposed restricted /proc access, nsfs sandbox setup, read-only fault-log placement and IPv6 address loss after DOWN. Raw logs and credentials remain ignored/private. Performance is reported only for the identified release snapshot, not selected across differing versions.

**Whole-host early-boot zero-gap and sudden power-loss recovery remain untested.** Physical NICs, general network managers, DHCP/SLAAC, WAN paths, storage power-loss durability and arbitrary root actors are outside this MVP. Old reviews/boot, reviews/mvp and reviews/deployment remain historical source snapshots; do not relabel them as this run.

```sh
.venv/bin/python -m tools.guard_report reviews/guard --current-source
```
