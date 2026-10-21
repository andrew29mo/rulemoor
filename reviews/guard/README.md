# Installed Boot Guard MVP evidence — 2026-10-21

Run `81c4797c3ed238b4`; executable source fingerprint
`b3524c2f36f5e3951cf0a8514e78eaa8736dbc525caead06ef8f557afc244618`.

**130 native macOS tests and 130 Linux portable tests passed**, zero failures/errors/skips. The exact executable manifests match. The [existing production-core mutation suite](mutations.json) also caught all 32 injected regressions by assertion; those controls cover the existing core/diagnostics/service, separately from the 24 new report controls. Separately, all 12 real VM phases passed, with 24 corrupted-report controls rejected. The fixtures installed the production wheel, exact base Guard unit and opt-in Agent dependency, with namespace/memory accounting overrides.

[JSON](guard.json) · [HTML](report.html) · [native receipt](native-unit.json) · [development attempt ledger](attempts.json) · [design and reproduction](../../docs/BOOT_GUARD.md)

## Measurements

All are single observations in the same Colima Linux VM. These different recovery contexts are not comparable benchmark modes; no aggregate speedup or recovery bound is claimed.

| Observed scenario | Guard open path (ms) |
| --- | ---: |
| Initial load | 15.299 |
| Recovery after rejected write | 43.926 |
| Agent TLS key absent | 15.381 |
| Reopen after crash/close faults | 16.194 |
| Orphan retirement/recovery | 30.789 |
| Partially confirmed boot | 58.546 |
| Committed boot | 54.505 |

The internal interval starts inside Guard.open and ends with the final OPEN receipt. It includes address preparation, recovery, SQLite, nft, link operations/readbacks; it excludes Python import/profile loading, the privileged setup step and full systemd startup. Failed attempts and intermediate state changes are not hidden by these success-path intervals.

| Memory sample | RSS bytes | VmHWM bytes |
| --- | ---: | ---: |
| Guard held before-up | 18694144 | 18694144 |
| Guard held after-up | 18698240 | 18698240 |
| Agent initial | 23408640 | 23408640 |
| Agent after partial boot | 23351296 | 23351296 |
| Agent after committed boot | 23265280 | 23265280 |

Guard samples are the actual installed process held in its ip subprocess call, excluding children; VmHWM is observed up to that point, not a normal entire-run peak. Agent samples are running daemon process RSS/VmHWM; its cgroup memory_current is separately retained in JSON. Guard cgroup MemoryPeak was `[not set]`, not zero, and no peak value is invented. These are VM process measurements, not native macOS or whole-VM memory.

Host stop/start plus control/verification/preparation intervals: partial boot 13.323 s; committed boot 12.882 s. The partial interval also includes preparation/commit of the next scenario. These are not management-access recovery times or SLAs.

## Observed correctness boundaries

* Production executor write rejection produces DEGRADED and DOWN; recovery follows explicit local fixture repair. No automatic untrusted-journal repair is claimed.
* Both SIGKILL hold points run the installed Guard with the same invocation/process identity; the subprocess is retired and actual close reads DOWN. An injected close-command failure leaves UP/FAULTED until separately observed manual rescue. PASS means these expected outcomes, not that every fault closes the link.
* A subscription-ready route-netlink observer records no link events during the tested Agent restart. This is one finite observation window, not whole-boot link/packet coverage.
* Both families have actual external-peer allowed echo, blocked connect-stage probes with live listeners, and new certified TLS access. An echo timeout is not accepted as firewall blocking.
* Pre-guard observations independently read both owned tables absent and the unchanged pending/committed journal; only then does formal recovery install both correct policies and open the link. Orderly shutdown rollback cannot explain the pending recovery result.
* All fixture units, source snapshot, credentials/state and namespaces were removed; root VM firewall digest was unchanged; final VM state is Stopped.

The [ledger](attempts.json) preserves four failed development runs and their source fingerprints, followed by successful snapshots. Failures exposed restricted /proc access, nsfs sandbox setup, read-only fault-log placement and IPv6 address loss after DOWN. Raw logs and credentials remain ignored/private. Performance is reported only for the identified release snapshot, not selected across differing versions.

**Whole-host early-boot zero-gap and sudden power-loss recovery remain untested.** Physical NICs, general network managers, DHCP/SLAAC, WAN paths, storage power-loss durability and arbitrary root actors are outside this MVP. Old reviews/boot, reviews/mvp and reviews/deployment remain historical source snapshots; do not relabel them as this run.

```sh
.venv/bin/python -m tools.guard_report reviews/guard --current-source
```
