# Boot design exploration receipts

* `exploration.json`: final frozen Linux VM run `eb08f5581fec7bc0`.
* `report.html`: exact rendering of that JSON, independently checked.
* `native-unit.json`: 119 passing macOS tests, same executable source manifest.

The nine phases contain four design explorations plus setup, handoff, post-boot
observations and cleanup. Twenty-seven corrupted-report controls were rejected. A
reported PASS includes **expected unsafe counterexamples**, notably a skipped
prerequisite, competing automatic activation and injected FAULTED cleanup; it is
not a claim that every trial kept the interface DOWN.

Audit the retained run with:

```sh
.venv/bin/python -m tools.boot_report reviews/boot --current-source
```

See [scope, reproduction and revised acceptance criteria](../../docs/BOOT_GUARD_EXPLORATION.md).
[Review findings and corrections](../../docs/BOOT_GUARD_REVIEW.md) cover the stricter
stage, process, cleanup, source and receipt checks. The audit also verifies
`native-unit.json` when it is present.

The installed production Controller/Agent were exercised. The gate itself is
experimental fixture orchestration and is not an installed feature. Interface
readbacks are sampled observations, not continuous packet capture.

Older `reviews/mvp` and `reviews/deployment` artifacts remain historical records
of their own manifests. Their current-source audit commands deliberately reject
this expanded source tree; they were not regenerated or relabeled as current
full-suite Linux evidence. Their frozen artifact consistency was checked, and
production `rulemoor/` files plus the default service unit are unchanged here.

No early-boot zero-gap, hard power-loss, physical NIC, arbitrary-root exclusion,
RSS reduction or performance improvement is established. Ignored raw logs,
credentials and VM state are not part of these public-ready receipts.
