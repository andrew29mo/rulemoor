# Pre-publication review

Status: MVP implemented and locally validated; repository remains Private. No project license selected. Publication is a separate owner decision.

## Evidence reviewed

- Native macOS and Linux each pass 41 portable/core/API tests using the same executable snapshot.
- Real Linux nft/netns/TLS validation passes all seven case groups, including six SIGKILL boundaries, two foreign-policy boundaries, old/queued TCP connection rejection, executor timeout, lost confirmation response, restart and graceful shutdown.
- Actual ENOSPC is reproduced in a proven 16 MiB tmpfs with a hard write ceiling; baseline and durable rollback are verified, and the mount is removed.
- Five production mutations are caught by assertions. Five corrupted evidence controls are rejected. Independent evidence audit checks source/run identities, trial statistics, cleanup and HTML consistency.
- Every timed application changes its policy; all ten trials are retained. RSS scope, VM scope, state allocation and single-observation recovery timings are explicit.
- The installed package is compared module-for-module against the validated checkout, not inferred from source tests.

See `reviews/mvp/`, `reviews/package-verification.json` and `docs/MEASUREMENTS.md`. Recorded source hashes, rather than a self-referential commit hash, identify tested executable inputs. `reviews/mvp/attempts.json` retains the history of failed/superseded attempts without treating them as current evidence.

## Problems corrected before release preparation

- TCP accept time alone could misclassify an already established backlog connection; the post-apply peer snapshot and real-network regression close that gap.
- SQLite PRAGMA failure occurred before the connection cleanup block; the production connection manager now closes that descriptor and the real corruption/tmpfs cleanup test passes.
- The CLI's original 64 KiB response read truncated valid large history. A reproducing regression now passes with a bounded 1 MiB response allowance.
- The first ENOSPC fixture mounted and filled in different mount namespaces. The corrected driver mounts, verifies filesystem identity/capacity, fills within a hard bound and unmounts in one live namespace.

## Files and privacy

Tracked files were inspected and pattern-scanned for embedded private keys, common GitHub/cloud credentials, home-directory paths and email addresses; none were found. No virtual environment, certificate/key, raw host log, state database, VM disk, toolchain download or personal AGENTS/settings file is included. Patterns do not guarantee detection of every possible secret format. Git uses a GitHub noreply author address.

## Repository access and remaining publication gates

Remote settings are retained in `reviews/security-settings.json`. The owner is the only collaborator, no invitations are pending, and the repository is Private with no detected project license. Dependabot alerts/security fixes are enabled. Actions use a read-only token, cannot approve PRs, and allow only two exact pinned actions. External-fork workflows are disabled. The optional workflow is manual-only; no remote CI pass is claimed.

GitHub rejected main branch protection with HTTP 403 for the current Private plan, and rejected Secret scanning enablement with HTTP 422. Neither is represented as enabled. Before publication, the owner must choose a license and explicitly authorize visibility change; available secret/push protection and main no-force-push/no-deletion protection must then be enabled and read back. No paid service or public visibility was enabled to bypass these limitations.

This review does not establish production qualification, independent security certification, systemd boot behavior, host reboot/power-loss durability, other nft/kernel versions or safety against an arbitrary privileged writer. A stopped agent still requires restart for recovery.
