# Boot design exploration review — 2026-10-21

Historical design-exploration evidence, preceding the installed
[Boot Guard MVP](BOOT_GUARD.md). Its source fingerprint remains historical;
use the audit without `--current-source` to check its own frozen receipts.


Two independent read-only reviewers first inspected implementation and raw
receipts, then compared the documentation. Their agreement was not treated as
execution evidence. The primary agent reproduced the accepted corrupt-report
cases, corrected the experiment/verifier, and reran the isolated VM and native
tests. Both reviewers subsequently inspected the fresh receipts.

## Findings and corrections

No confirmed defect was found in the production recovery state machine by this
bounded review. Four evidence/report issues were corrected:

| Finding | Before | Correction and challenge |
| --- | --- | --- |
| Incomplete stage history accepted | Keeping only `vm-initial` could still pass independent verification | Require the exact ordered build, upload, guest phases, orderly restart and cleanup stages, all with successful bounded outcomes. Delete/duplicate-stage controls must fail. |
| Crash/cleanup identity underchecked | A non-SIGKILL result or a CLOSED receipt for an UP/different interface could pass | Capture held PID/start ticks and namespace, before/after InvocationID, signal result 9, and same-identity DOWN observations. Independently challenge owner and writer locks with the exact structured ownership rejection. |
| Fresh receipts and namespace replacement underchecked | Wrong generation/digest/namespace in the revalidated receipt, or a claimed recreation using the old inode, could pass | Verify the complete new open receipt against the restored journal/policy and identity. Pin the old namespace across replacement, require a distinct successor inode in the same boot, and verify failed-start cleanup on that successor. |
| Report could briefly appear successful before final cleanup | Producer set its success flag before cleanup/final VM-state checks | Keep the run incomplete through cleanup. HTML independently verifies full receipts and negative controls before showing overall PASS; incomplete data with `passed=true` remains incomplete. |

Installed package provenance now validates the `site-packages` origin as well as
all production module hashes. The audit binds the optional native receipt to the
same manifest, unique test IDs/count and zero failures/errors/skips; without that
file it explicitly reports a VM-only audit.

The probe refuses leftover units before writing its own configuration. Cleanup
only resets the named probe units and does not invoke a global reset when the
list is empty. These are dedicated-VM fixture safeguards, not protection against
arbitrary privileged processes.

## Fresh evidence

The retained [JSON](../reviews/boot/exploration.json),
[HTML](../reviews/boot/report.html), and
[native receipt](../reviews/boot/native-unit.json) belong to new run
`eb08f5581fec7bc0`, source fingerprint
`a300356be0c7e71f18aec8979cd95c9c53ef93bab388f7201bea6f10758f99a7`.
Old data was not relabeled to this source.

* Nine actual VM phases, including the four bounded explorations and one orderly
  stop/start, passed; 27 deliberately corrupted-report controls were rejected.
* Both held-point service deaths report `Result=signal`, `ExecMainStatus=9`,
  matching invocation/PID observations; both separate lock contenders are blocked.
* Pending journal projections match across shutdown and the pre-restoration boot
  observation; both tables are initially absent, then both baseline policies match
  before the link is enabled. This excludes pre-shutdown rollback as the explanation.
* The pinned old namespace differs from its successor. Same-boot missing-policy
  reconciliation fails and leaves the successor interface DOWN.
* Same-source macOS tests: **119 passed, zero failures/errors/skips**. Eight test
  methods challenge the report boundaries. The 119-test Linux portable suite was
  not run as part of this VM experiment.
* Cleanup removed probe units/namespaces, base fixture state/credentials and the
  uploaded source. The root VM firewall digest was unchanged and the VM stopped.

Recheck with:

```sh
.venv/bin/python -m tools.boot_report reviews/boot
.venv/bin/python -m unittest discover -s tests -p test_boot_report.py
```

## What remains outside this evidence

This remains an experimental gate using the **installed production recovery
implementation**. The unchanged production systemd service is not an early loader.
The Agent delay/restart uses its installed entry point in an experimental unit.
The direct failing nft ExecStarts test prerequisite failure, not a production
backend recovery-write failure; that integrated fault remains an MVP criterion.

Controller/writer competition is checked at the held points. A delayed retired
executor during this new gate handoff is not newly tested. The receipt is
informational and the gate always reconciles live state; namespace replacement
also removes its tables, so this case does not independently prove stale-identity
rejection when policy remains otherwise valid.

Unsafe dependency/manager counterexamples and injected UP/FAULTED cleanup are
expected observations, not safety successes. UP-before-cleanup is an observed
window. No continuous packet/link trace, general network-manager integration,
physical NIC, kernel hang or arbitrary-root exclusion was established.
**Whole-host early-boot zero-gap protection and sudden power-loss recovery remain
untested.** The [MVP criteria](BOOT_GUARD_EXPLORATION.md#proposed-first-mvp-acceptance-criteria)
retain these distinctions and the remaining integrated-test work.
