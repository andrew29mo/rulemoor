# Agent-assisted correctness review — 2026-10-21

Two read-only reviewers formed separate first passes from the production source, tests and retained evidence. Findings were reproduced, corrected by the primary authoring agent, and reviewed again. Agreement alone was not used as proof: regression tests, negative controls and a fresh same-source macOS/Linux run support the conclusions below. The repository remains Private; no project license was selected.

## Findings and corrections

| Finding | Correction | Evidence |
|---|---|---|
| A SQLite transaction could commit COMMITTED, then checkpoint initialization could fail; confirm incorrectly reverted memory to pending and later rolled back the committed policy. | Treat post-commit checkpointing as maintenance, expose a warning, preserve the durable decision. Pre-commit persistence failure still cannot confirm. | A reproducing real-SQLite regression; actual nft confirmation with an injected post-commit checkpoint connection error, retained past the deadline and through controller reopen/recovery; negative mutation caught. |
| An executor could naturally exit between identity validation and pidfd open/signaling. ESRCH permanently degraded recovery instead of reconciling known policy. | Handle only ProcessLookupError as natural exit; continue to writer-lock acquisition and actual policy reconciliation. Other failures remain fail-closed. | Deterministic syscall-error injection at both windows plus a permission-error control, using production retire and real SQLite. These are not claimed to be observed Linux scheduling races. Separate live-orphan tests exercise real process retirement. |
| Two-second socket timeout was inactivity-only; unauthenticated clients could trickle headers indefinitely and retain all sixteen slots. | Add a five-second absolute accepted-connection lifetime. The handler owns close/slot release; the deadline only shuts down I/O. | Before-fix real TLS reproduction, scaled portable regression, mutation control, and a real Linux finite sixteen-connection test with default timings. |
| Old and new fencing-test candidates were identical, so a delayed overwrite could not be distinguished by policy equality. | Use old port 59992 and new port 59993; verify the old PID identity exited and retain actual post-release kernel policy plus generations. | Real orphan, recovery, newer commit and delayed-release test. Verification rejects missing/empty PID identity, invalid old policy and identical candidate policies. |
| Verifier could accept omitted stage/recovery evidence; optimized Python could remove bare validation assertions. | Require stage/test/case identities, necessary evidence and source fingerprints; refuse optimized validation. | Seventeen evidence-corruption controls and a portable `-O` rejection test. |

History output was also moved outside the controller lock. The original slow-reader attempt did not reproduce a long kernel-socket stall on macOS; a deterministic blocked-output regression demonstrates that network output can no longer hold up controller decisions. This is a preventive correction, not an observed production outage.

## Final evidence

The agent-reviewed run `04dc27f97d65586b`, retained in commit `f50e7a7`, had native macOS and Linux each pass 48 tests, eight production mutations are caught by assertion failures, seventeen corrupted evidence controls are rejected, and all eight real-Linux case groups pass. The raw source manifest/run ID, unit test IDs, distinct fencing policies, process identity, actual kernel readbacks, cleanup and full measurement trials are retained. Both reviewers rechecked that agent-review run; the recovery reviewer also reran the three identity/policy tamper controls.

The installed package is separately compared against the validated module files. Raw local host logs, generated credentials, personal agent settings and orchestration logs are not publication artifacts.

## Interpretation and limits

The timing experiment retains ten sequential, policy-changing TLS operations, split between five confirmations and five cancellations. Its RSS is the agent process's kernel VmHWM, excluding nft children, clients and VM memory. The latest values in `docs/MEASUREMENTS.md` may describe a later pre-publication run; no before/after speedup is inferred.

The five-second lifetime bounds a finite set of slow connections. Continuous replacement connections can still deny admission and prevent an operator from confirming; the timeout/recovery path is intended to fail safe, not guarantee availability under attack. No production SLA, comprehensive DoS resistance, systemd boot validation, host-reboot or power-loss proof is claimed. Private-plan branch protection and Secret scanning limitations remain as recorded in `reviews/security-settings.json`.

Subsequent pre-publication changes and their latest evidence are documented in `PUBLICATION_REVIEW.md`. This historical agent review does not imply the two reviewers examined those later changes.
