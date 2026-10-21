# Agent-assisted startup and recovery review — 2026-10-21

Reviewed starting commit: `1bdc75c`. This records the startup review before the later management-preflight feature; latest executable-source evidence is in [deployment validation](DEPLOYMENT_VALIDATION.md). Two read-only reviewers independently inspected production startup/stale-operation behavior and installed-service/report evidence. The main agent reproduced the findings, implemented the fixes and ran the system tests. Their agreement is not substituted for execution evidence; follow-up review of known fixes is not described as another blind review.

## Findings and corrections

1. **Legal operation ID rejected on restart.** The API permits `initial`, but the prior snapshot validator treated every such ID as provisioning. Both a normally generated pending and committed transaction became DEGRADED after reopen. The pending candidate remained installed rather than being restored. Initialization is now distinguished by its exact common-field shape with no candidate, not the ID alone. Portable tests cover both restart paths and stale confirmation/cancellation during a newer pending change. The installed-service persistent-failure scenario also uses `initial` and must restore its baseline after local repair.
2. **Inconsistent baseline could be used for rollback.** Changing only the baseline of a production pending snapshot to another valid policy passed the prior validator and allowed recovery to install that policy. Unfinished states now require current/baseline equality before process fencing or backend access. A regression challenges PREPARED, APPLYING, AWAITING_CONFIRM and ROLLING_BACK; it requires blocked backend access, preserved original data and refused mutation. COMMITTED may legitimately differ from its old baseline. This is a consistency guard for known invalid data, not journal authentication or arbitrary corruption repair.
3. **Rate-limit receipt had no upper time bound.** A future microsecond timestamp (`10**30`) still passed the old artifact verifier. Receipts must now use the same boot and fall between the positive integer fault-start and failed-state observation-start endpoints. Nondecimal, non-string and out-of-window timestamps are rejected.
4. **New memory observations were not joined to the scenario boot.** Changing repaired-service memory to a different boot still passed. Both diagnostic and repaired-service samples must match the setup boot; the diagnostic invocation must also match its observed service instance. Stable per-process sampling checks remain in place.

The three new production regression methods produced six assertion failures against the prior implementation (two ID paths plus four inconsistent-baseline phases). Reverting initialization classification or removing the baseline/current guard is caught by an assertion mutation. A report regression separately challenges clock/boot boundaries. Three new evidence-corruption controls replace receipt timing, boot and invocation with inconsistent values; all must be rejected.

## Execution evidence for this review (historical)

- Same executable snapshot `2577be96c26b221f1f07cad8c4c4bcffaca12c9f9198bc4a7ff0f13d99f3f80c`: native macOS and Linux each pass **70 tests**, with no skips; **17 production mutations** are caught by assertions.
- All **8 container Linux groups** and **17 container evidence controls** pass; installed production systemd execution separately passes **9 groups** and **21 evidence controls**.
- Native/container run `96508b08bb2e0723`; installed-service VM run `436c8a5408819100`. Installed package hashes, complete stages, monotonic intervals, kernel readbacks, generations, stale-request traces and exact HTML/JSON equality are audited.
- The pending journal is read on the new boot before Agent startup and compared with its pre-shutdown value. This distinguishes startup recovery from a rollback completed during orderly shutdown.
- Both workflows clean up their fixtures and stop the VM. Private host logs, credentials, state databases and VM files stay ignored/local. Metrics in that run were recomputed from every retained trial; run-to-run differences are not described as improvements.

## Operational limits

The persistent failure uses a missing TLS key and real nonzero production ExecStart exits. Rate limiting bounds retries; while the service is stopped, the pending candidate remains and no deadline timer executes. Local cause repair plus explicit reset/start is tested; automatic repair of untrusted state is not. Diagnostic reprovision is explicitly a disposable fixture procedure with credential rotation.

Two VM stop/start cycles use orderly shutdown. **Sudden power loss, native segmentation faults and uninterruptible storage I/O are not tested.** Namespace-local TLS readiness is not WAN availability, a recovery-time bound, fail-closed early boot or production qualification. VmHWM, service-cgroup memory and total VM RAM retain different scopes.

[Method and measurements](DEPLOYMENT_VALIDATION.md) · [Deployment JSON](../reviews/deployment/deployment.json) · [HTML](../reviews/deployment/report.html) · [Native/container evidence](../reviews/mvp/combined.json)
