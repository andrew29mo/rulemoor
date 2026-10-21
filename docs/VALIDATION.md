# Validation method

## Native scope

`python -m tools.unit` runs production schema/compiler/core decisions, real local TLS API/CLI transport checks, and failure/timeout handling of the validation process wrapper. Memory-backend tests deliberately isolate state-machine contracts. They do not establish nft semantics, kernel reachability or native macOS agent performance. OpenSSL is needed to create temporary test certificates, which are deleted with the temporary directory.

`python -m tools.mutations` copies source into isolated temporary directories, changes twenty-eight production decisions and requires an existing assertion to fail for each. Import/syntax failures, timeouts or a bare nonzero exit do not count as caught mutations.

## Linux scope

`tools.linux_validate` runs inside a disposable VM container. It repeats portable tests and runs real nftables/network namespace/TLS tests through the production Controller, NftBackend, service and CLI request transport. The only alternate frontend is the fault driver, which calls these same production methods and holds process boundaries for SIGKILL; it is not another recovery implementation.

The cases include:

- Kernel dry-run nonmutation, invalid-batch atomicity, unrelated-table preservation, full 32-rule compilation and ordered/default-drop readback.
- Established old keepalive versus blocked fresh connection, old-confirm rejection, timeout restoration, fresh reconnect and positive confirmation surviving its deadline.
- SIGKILL at prepared, executor intent, executor held, kernel-applied, awaiting-confirm and rollback-applied boundaries; repeated recovery and old-generation rejection.
- An inherited lock held by the actual nft binary; a killed parent with an orphan executor; verified retirement followed by a newer commit which survives delayed old release.
- Unknown foreign policy before readback or during restart recovery: DEGRADED and no blind overwrite.
- Actual TLS service restart, malformed-executor-record startup with an accessible DEGRADED status and blocked writes, graceful shutdown, pre-apply TCP backlog rejection, and SIGKILL after confirmation commit but before the HTTP response.
- Actual SQLite commit followed by an injected checkpoint-connection error, with real kernel readback and confirmation preserved past the deadline and controller reopen. Actual service-process restart is covered separately. Native tests separately inject ESRCH at both pidfd boundaries and verify permission failures remain fail-closed.
- Sixteen unauthenticated header-drip TLS connections using the default 5-second absolute lifetime: rollback still occurs, the finite batch expires and a fresh confirmation succeeds. This is not continuous-attack protection.
- Actual ENOSPC in a bounded 16 MiB tmpfs, baseline restoration after releasing reserve, durable rollback readback, state-budget refusal, corrupt-journal refusal and test mount cleanup.
- Ten timed policy changes with every trial retained, alternating confirmation/cancellation, plus worker RSS and state-directory allocation.

`RULEMOOR_FAULT` is an internal fault-injection environment variable. Never set it in a deployment; the sample unit clears it. No remote API enables fault hooks.

## One command, same snapshot

```sh
PYTHON=.venv/bin/python tools/validate-local
```

This installs checksum-pinned Colima/Lima into ignored local storage and uses an existing Docker CLI. A dedicated Colima home/profile is used by default. It starts only an absent/stopped profile; it refuses to disturb an already running one. Native and container runs receive the same immutable file snapshot and run ID. Executable Python, package configuration, Dockerfile, service unit, wrapper and toolchain lock hashes are recorded. README/results changes do not alter the executable snapshot.

Existing installations can explicitly provide all three overrides:

```sh
RULEMOOR_TOOLCHAIN=/path/to/toolchain/bin \
RULEMOOR_COLIMA_HOME=/path/to/dedicated-colima-home \
RULEMOOR_DOCKER_CONFIG=/path/to/docker-config \
PYTHON=.venv/bin/python tools/validate-local --output results/run-example
```

Do not run another project against the selected profile concurrently. Each run requires a fresh output directory. Container constraints: no network egress, no bind mounts, no privileged mode, 2 vCPU, 768 MiB memory, 128 PID limit, NET_ADMIN and SYS_ADMIN only, within the disposable VM. The extra mount capability is for isolated namespace/tmpfs tests, not a production-agent requirement. No host NIC, DNS or firewall is changed.

Nonzero exit, timeout, missing/empty evidence, run/source mismatch, OOM, source drift or cleanup failure prevents a passing receipt. SIGINT/SIGTERM trigger bounded cleanup; a forcibly killed host driver, host crash or VM-manager failure can still require manual container/VM cleanup. Raw host logs stay under ignored `results/` because they may contain local filesystem paths.

The driver verifies container exit and removal, VM stopped state, namespace/process cleanup and unchanged container-root firewall. It also requires zero workers in both test namespaces after every case, before later measurements. Fixture cleanup signals owned process groups even when their direct parent already exited; this does not authorize production to signal a PID from malformed metadata. It challenges the evidence verifier with seventeen corrupted/missing-evidence controls, including invalid old-writer identity, identical fencing policies and omitted stages. Optimized Python (`-O`/`PYTHONOPTIMIZE`) is refused because disabling assertions must not create false passing evidence. Individual test IDs are retained for both platforms. `python -m tools.audit_evidence reviews/mvp` independently rechecks current-source correspondence, raw trial summaries, run IDs, cleanup and exact HTML/JSON consistency.

Retained publication artifacts contain only structured records and the generated report, not credentials, full host logs, VM disks or container contents. An artifact's pass applies to its recorded source snapshot; later executable changes require a new run.

## Remote CI

A manual-only GitHub Actions workflow repeats portable contracts on Linux/macOS. It is not the real-kernel validation and is not required by the local workflow. It has not been dispatched for this MVP; no remote CI pass is claimed. Actions are pinned and the workflow has read-only permissions.

## Actual systemd and orderly VM restarts

The separate [deployment suite](DEPLOYMENT_VALIDATION.md) installs the production wheel and unit directly in an isolated Linux VM. It verifies systemd automatic restart, cgroup orphan cleanup, TLS readiness, stale operations, missing kernel rules after a changed boot ID, committed-policy restoration and foreign-policy refusal. This is not systemd simulated in a container. It restarts the selected VM twice and requires explicit selection of a stopped dedicated profile. It uses a different Linux userspace from the container suite; its memory/timing observations are reported separately. Power-loss recovery is not tested.

The deployment auditor additionally requires the complete VM stage sequence, an isolated installed-package origin/hash probe, unchanged pending journal across the orderly reboot before Agent startup, raw pending/committed stale-request observations and monotonic timing endpoints. Its twenty-six corruption controls include omitted stages, false package origin, rolled-back pre-boot journal, stale generation, infinite/missing intervals and invalid memory identity. Four portable measurement/report regressions reject nonfinite values, inconsistent clocks and missing-duration-as-zero presentation.

## Invalid snapshots and persistent startup failures

Portable tests write malformed, incomplete, nonfinite, oversized and missing snapshots into real SQLite databases, then call production startup. They require diagnostic status, refused mutation, unchanged original data and no backend signaling/readback. The oversized case pads an otherwise valid snapshot, so removing the size guard is caught independently of schema rejection. Two production mutations separately remove schema validation and the size bound.

The actual-systemd suite separately checks diagnostic startup from a JSON-list snapshot and sustained nonzero starts from a withheld TLS key. The former stays available for diagnosis without policy writes; the latter exhausts the unit's restart limit and requires local cause repair and an explicit reset/start before baseline recovery. These are different failure classes. The malformed-state fixture preserves its evidence, stops writers and reprovisions a reviewed disposable baseline with rotated credentials for subsequent cases; that is not a production automatic-repair feature. Native segmentation faults, uninterruptible storage I/O and power loss are untested.

## Agent-assisted startup/recovery review

[The follow-up review](STARTUP_REVIEW.md) reproduces the legal `initial` operation-ID regression in both pending and committed state, rejects inconsistent unfinished baseline/current pairs before backend access, and bounds rate-limit receipts to the observed fault window. Three production regressions plus one report-boundary test extend the retained suite. Two additional production mutations independently reinstate the ID regression and remove the baseline guard. Actual installed-service restart-limit recovery uses `initial` as its pending operation ID; its baseline restoration and later stale-request rejection remain mandatory. Poison/repaired-service memory samples must belong to the setup boot; diagnostic invocation attribution is also required. These checks do not establish arbitrary journal repair or untested failure recovery.

## Configured management diagnostics

The [management preflight](MANAGEMENT_PREFLIGHT.md) tests exercise formal configuration parsing, NEW own-policy order and NEW/ESTABLISHED external input modeling, read-only external rule modeling, conservative uncertainty, command bounds/reaping, Controller admission and local TLS error/confirmation paths. Six additional production mutations accept null configuration, hide an unknown action behind a later nonmatch, remove admission, hide uncertainty, ignore the first terminal verdict and remove the ruleset byte limit; each must fail an assertion. The installed-service VM suite adds a configured-service scenario with actual TCP and foreign rules at priorities -100 and 10, plus an unsupported address condition, rule preservation and old/fresh confirmation checks. Five additional report-corruption controls challenge denied admission, foreign-rule preservation, uncertainty, old confirmation rejection and observed TCP blocking. Container operation measurements remain unconfigured and are not an overhead baseline for this scenario.

The management-preflight follow-up additionally tests the formal service main entrypoint with real SQLite pending state and missing/null configuration. Recovery must finish before admission configuration rejects API startup. Cancel, deadline, restart and reboot recovery are checked against a baseline that the current management guard would reject as a new candidate. Two mutations remove startup reconciliation or ESTABLISHED input analysis; assertion failures are required. The isolated installed-service suite repeats missing/null recovery and challenges TCP refusal, absent recovery probes and changed listener identity.

## Dual-stack minimum slice

[Dual-stack tests](DUAL_STACK.md) call the formal dual schema/compiler/reference, strict journal validation, Controller, IPv4/IPv6 TLS sockets and literal-family CLI transport. Eleven portable test methods cover family-independent receipts, rollback/recovery, persistence failure, mode/partial-table drift and tcp6 parsing. Three production mutations deliberately permit one-family commit, forget failed persistence rollback or mislabel an actual IPv4 confirmation as IPv6. The installed-service VM adds cross-veth two-family access, IPv6 blocking with repeated IPv4-only partial confirmation, common-deadline restoration, two-family commit, static neighbour discovery, partial-confirmation SIGKILL recovery and stale-request rejection with distinct policies. Seven additional evidence controls challenge incomplete family commitment, wrong rollback/transport, foreign changes, missing clocks, partial crash recovery and cleanup. Dual VM reboot, routed PMTU and power loss are not established.
