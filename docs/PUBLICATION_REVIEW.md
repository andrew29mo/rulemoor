# Final pre-publication review — 2026-10-21

Status: code, tests, documentation and current local evidence reconciled. The owner subsequently authorized publication: the repository is now **Public**, with the **MIT License adopted by the owner**. The pre-publication findings below remain applicable; post-publication checks are recorded at the end.

## Current evidence

- Native macOS and Linux each pass **111** production-core/API/tool tests from the same immutable executable snapshot. Portable kernel behavior is represented by a memory backend; actual nftables/network evidence comes from the Linux VM case groups.
- All **eight** real Linux nft/netns/TLS groups pass: atomicity, management connectivity, six crash boundaries/two foreign-policy cases, process recovery, backlog/response loss, storage faults, finite slow clients and measurement.
- **Twenty-nine** production mutations are caught by assertion failures; **seventeen** malformed or missing-evidence controls are rejected. Optimized validation is refused rather than silently removing assertions.
- Source fingerprints, individual test IDs, run IDs, raw trials, summary recomputation and exact HTML/JSON consistency are rechecked by `tools.audit_evidence`.
- Both test namespaces have zero remaining workers after each case, before subsequent tests or measurements. Final namespace/container cleanup, unchanged container-root firewall and stopped VM are verified.
- Built wheel modules are compared with the validated checkout; wheel and source distributions are checked for MIT metadata and matching license/notice files. Current records are in `reviews/mvp/` and `reviews/package-verification.json`.

`docs/MEASUREMENTS.md` reports the current run's endpoint medians/ranges, daemon VmHWM and state-directory allocation. Ten changing-policy trials are retained, split between five confirmations and five cancellations. TLS transport/checks/journal costs are included; Python command startup, preparatory status requests and the CLI confirm command's additional status fetch are excluded. RSS excludes nft children, clients and VM memory. No speedup, tail-latency, throughput, total-deployment-memory or production-SLA claim is made.

## Corrections in this final review

A malformed executor identity file previously escaped startup as JSON/type errors instead of producing the documented DEGRADED status. Recovery now bounds the record to 4 KiB, validates token/field types and refuses malformed data before any process lookup or signal. Production exposes DEGRADED and blocks new writes; it does not guess a PID or blindly restore over uncertain ownership. A portable regression and real TLS/Linux startup scenario cover this behavior. The regression failed before the correction, and a production mutation reintroducing the failure is caught.

The added corrupt-record fixture also exposed a cleanup gap: a parent process may already be dead while its owned group still contains an orphan. Fixture cleanup now retires owned groups regardless of parent status and verifies the known orphan exited. The runner prevents continuation to measurement with namespace workers remaining. The intermediate run is recorded as superseded and is not the source of published timing values.

Prior agent-assisted findings and their historical evidence are in [AGENT_REVIEW.md](AGENT_REVIEW.md); that review is not presented as an independent review of these later changes.

## Files and privacy

Current tracked contents and reachable Git-history blobs were inspected for unexpected binaries/large files, private keys, common GitHub/cloud credential formats, personal home paths and private contact addresses. No findings were observed. Git commit authors use the owner's GitHub noreply address. These checks are not a guarantee of detecting every possible secret format.

No virtual environment, raw host log, generated certificate/key, state database, toolchain download, VM disk, personal AGENTS/settings file or orchestration log is tracked. The structured test artifacts contain documentation-range/loopback addresses and test process identities; actual credentials are not retained. Runtime/build outputs remain ignored. No model/data asset or vendored runtime dependency was added.

## License and access

README, package metadata and LICENSE consistently identify MIT, copyright (c) 2026 Andrew Yuan. LICENSE and THIRD_PARTY_NOTICES.md are included in Python distributions. Third-party tools retain their own licenses as described in `THIRD_PARTY_NOTICES.md`; no image/binary redistribution or legal clearance is asserted.

GitHub was rechecked after publication: Public, owner-only write/admin access, no pending collaborator invitations, read-only Actions tokens, no PR-approval permission, an exact pinned-action allowlist and required SHA pinning, approval required for all external contributors, and enabled Dependabot alerts/security fixes. See `reviews/security-settings.json`. The optional portable workflow remains manual-only; no remote CI pass is claimed.

Earlier Private-plan attempts to enable main protection and Secret scanning were rejected by GitHub (403/422). Following explicit owner authorization to publish, main protection, Secret scanning and push protection were enabled and read back successfully. No paid service was enabled.

## Remaining limitations

This remains a single-node input-table MVP with legacy IPv4 and explicit dual-stack modes for the documented kernel/nft environment. A stopped agent has no running rollback timer. The later deployment suite adds actual systemd and three orderly VM stop/start cases (two legacy IPv4 and one partially confirmed dual deployment); power loss, fail-closed early boot, arbitrary host boot ordering, arbitrary privileged writers, continuous connection-replacement attacks, other architectures and production qualification remain unestablished. Malformed metadata intentionally requires operator recovery, not automatic adoption.

## Owner-authorized MIT adoption — 2026-10-21

The owner selected MIT after the correctness review. README, SECURITY.md, package metadata and third-party notices were updated together; historical review wording is explicitly historical. Setuptools >=77.0.3 is required for SPDX license metadata and explicit license-file inclusion. This packaging-only change receives a fresh same-source macOS/Linux run so the retained evidence fingerprint continues to match the current package inputs. At that MIT-adoption stage, production Python code and tests were unchanged from commit `3c9f4ae`.

The MIT validation's first attempt failed during fresh dedicated-VM startup with a host PermissionError; the runner reported failure and verified the VM stopped. The successful retained run uses the documented explicit overrides for the previously validated dedicated Colima VM. This run does not establish successful first-time provisioning with the default VM home. Both attempts are recorded in `reviews/mvp/attempts.json`; raw host logs and VM files remain local.

## Owner-authorized publication — 2026-10-21

The repository is Public and GitHub identifies the license as MIT. Main protection applies to admins, prohibits force pushes/deletion, and retains owner direct pushes without mandatory PR reviews or required checks from the manual-only workflow. Private vulnerability reporting, Secret scanning, push protection and Dependabot are enabled. Actions allow only the two explicitly pinned actions, use read-only tokens and cannot approve PRs; all external contributors require approval for eligible fork PR workflows. Current settings and point-in-time alert observations are retained in `reviews/security-settings.json`. A zero alert count does not establish completion of asynchronous background scans.

Local macOS/Linux validation run `97f20111c14d7117` was re-audited against the unchanged executable snapshot. Publication updates documentation/security records only; no new performance result or remote CI pass is claimed. The earlier failed fresh-VM startup and successful explicit-existing-VM run remain disclosed above.

## Post-publication deployment recovery work

[Deployment validation](DEPLOYMENT_VALIDATION.md) adds installed-unit, automatic restart and orderly VM boot evidence. The earlier MIT/publication run references above are historical; `reviews/mvp/` now retains the latest same-source portable/container run and `reviews/deployment/` retains the separate actual-systemd VM run. Executable changes receive fresh validation; no abrupt power-loss recovery is claimed.


The current dual-stack update passes **111 tests per platform, thirty-two production mutations, seventeen original evidence controls, eight container Linux groups and fifteen actual-systemd deployment groups with sixty-five additional evidence controls**. Both suites record executable snapshot `5d2899bf453b3f6491afb0f7e9ebf52f70cf339035e205705985eb457af973ac`. The deployment run is `c6c726cffd12db8e`; the native/container run is `1344705fc9496855`. Failed/superseded deployment attempts remain visible; current cleanup verifies removal and a stopped VM.

## Deployment evidence audit

The follow-up [deployment review](DEPLOYMENT_REVIEW.md) reproduced a checkout-shadowed installation check and overly permissive artifact guards. Current records require isolated site-packages origin/module hashes, an unchanged pending journal read before new-boot Agent startup, pending/committed stale-request traces, finite recomputed monotonic intervals and stable process-associated memory. That earlier audit added four portable regressions; the current total includes six later malformed-snapshot regressions. Power-loss recovery remains untested.

## Persistent startup failure hardening (historical first pass)

A valid SQLite file containing an unusable JSON snapshot previously raised during startup. The snapshot now receives a 64 KiB bound and strict structural/policy/phase checks before fencing or kernel writes. Known invalid data is preserved and reported as DEGRADED. Six portable regressions and two production mutations challenge the guards; the installed real service also receives a JSON-list snapshot. The persistent missing-key case separately proves actual systemd rate limiting, unchanged pending rules/journal while stopped, and baseline recovery only after local repair/reset/start. Structured current-fault journal evidence is required because this systemd version retains Result=exit-code. Eighteen artifact-corruption controls include a missing rate-limit receipt. No unconditional crash recovery, CPU/log saturation protection, native segmentation-fault recovery, hung-I/O recovery or power-loss pass is claimed.

## Agent-assisted startup review (before management preflight)

The [follow-up review](STARTUP_REVIEW.md) found and fixed a legal operation-ID compatibility regression, a missing unfinished baseline/current invariant, and gaps in rate-limit timestamp and new memory-sample attribution. The before-fix regressions failed by assertions. Both reviewers rechecked the targeted fixes; execution evidence comes from new same-source native/container and actual installed-service runs, not reviewer agreement. Current counts and artifacts are above. No native segmentation fault, hung I/O, sudden power loss, continuous availability or independent rollback capability is established.

## Management preflight and read-only external diagnosis

The new [opt-in management preflight](MANAGEMENT_PREFLIGHT.md) declares local IPv4 TCP ports and gates new own-policy changes before intent/kernel writes. Missing configuration is explicit; external conflicts/unknowns remain diagnostic warnings. Production readers are bounded and reaped, diagnostic response data is excluded from durable state, and new TLS confirmation remains mandatory. Tests exercise formal parsing/evaluation/Controller/API; the installed-service VM case additionally verifies actual TCP drops, foreign-rule preservation, uncertainty and old/fresh TLS confirmation. Two independent agents reviewed the logic and evidence; their findings and known-fix rechecks are recorded in [PREFLIGHT_REVIEW.md](PREFLIGHT_REVIEW.md). No full topology simulation, WAN reachability or independent rollback is claimed. Current-source artifacts/metrics above supersede prior runs without claiming speed improvements.

## Dual-stack minimum slice

The [dual-stack implementation](DUAL_STACK.md) followed the startup and management-preflight reviews; its dedicated agent review is recorded below. Current tests additionally verify explicit paired ip/ip6 policies, actual-family fresh TLS confirmations, durable partial receipts and whole-policy timeout/restart restoration. The installed-service fixture uses static cross-namespace veth peers, refuses legacy adoption, checks a kernel-rejected second-family transaction without changing either policy, observes IPv6 neighbour discovery, rejects stale operations and preserves foreign tables. Its client namespace/veth cleanup is required. The later dual recovery extension adds a partial-confirmation dual VM boot; committed-only dual boot, general IPv6 topology modeling, routed PMTU, SLAAC, zero-downtime and power loss are not established. ICMPv6 is explicitly accepted before TCP rules.

## Agent-assisted dual-stack evidence review

The [dual review](DUAL_REVIEW.md) independently inspected production behavior and challenged copied artifacts. It found verifier gaps for restart identity and cross-boot/operation receipts, then added strict linkage and six evidence-corruption controls. Each stale request now has immediate journal and both-family kernel readbacks before legitimate confirmations. No production dual compiler/state-machine/TLS change was required by confirmed findings. Current source/run evidence above includes these changes; the original dual pass is historical. ICMPv6 remains explicitly permissive, and the later dual boot/orphan extension is separate from that review; power loss and broader IPv6 qualification remain untested.

## Actual dual VM boot and orphan executor extension

[Direct recovery evidence](DUAL_RECOVERY.md) now covers a partially confirmed dual deployment across the third orderly VM restart, including pre-Agent pending journal and absent-table reads. A held executor deliberately survives its Agent outside the unit cgroup and is retired by the installed Agent before writer ownership and a distinct dual successor. Late release preserves both policies in the finite observation. Four portable regressions, one retirement-removal mutation and eight evidence controls complement the actual process/kernel checks. The first helper-import failure is disclosed; the successful run validates installed module bytes and cleanup. Production state-machine/compiler/TLS code was unchanged in this extension. No abrupt power-loss pass is claimed.

## Dual VM recovery evidence review

[The independent follow-up review](DUAL_RECOVERY_REVIEW.md) found contradictory old HTML/validation scope text and an overstatement of endpoint readbacks as continuous observation. The renderer, regression assertion and documents were corrected; the same-source native/container and actual-systemd suites were rerun. Runtime recovery code was unchanged. The pending pre-Agent journal, both baseline tables, surviving orphan lock and retirement-before-successor invariants remain required. No power-loss pass is claimed.

## IPv6 declared-port preflight extension

[Dual preflight](DUAL_PREFLIGHT.md) now separates IPv4/IPv6 admission and supported foreign input diagnostics, with bounded read-only inventory. Unknown/unavailable IPv6 is never inferred safe from IPv4. Own denials gate new apply; external results remain warnings and baseline recovery bypasses admission. New formal and configured-service tests preserve both fresh confirmations and foreign rules. Configured-guard VM reboot, full topology, boot-time protection and power-loss recovery are not claimed.

## IPv6 preflight evidence review

[Independent follow-up review](DUAL_PREFLIGHT_REVIEW.md) reproduced two verifier/observation gaps: unrelated partial confirmation receipts could pass, and an intermediate foreign-table change restored by cancellation could evade end-of-sequence checks. Exact receipt-chain binding, an exported normal restoration baseline and per-operation foreign readbacks now challenge these cases. Two formal verifier regressions and eight corruption controls complement full same-source reruns. No production runtime defect was reproduced; the review does not expand the documented deployment guarantees.
