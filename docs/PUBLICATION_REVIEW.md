# Final pre-publication review — 2026-10-21

Status: code, tests, documentation and current local evidence reconciled. The repository remains **Private**, with **no project license selected**. Publication and licensing remain separate owner decisions; this review does not authorize either.

## Current evidence

- Native macOS and Linux each pass **49** production-core/API/tool tests from the same immutable executable snapshot. Portable kernel behavior is represented by a memory backend; actual nftables/network evidence comes from the Linux VM case groups.
- All **eight** real Linux nft/netns/TLS groups pass: atomicity, management connectivity, six crash boundaries/two foreign-policy cases, process recovery, backlog/response loss, storage faults, finite slow clients and measurement.
- **Nine** production mutations are caught by assertion failures; **seventeen** malformed or missing-evidence controls are rejected. Optimized validation is refused rather than silently removing assertions.
- Source fingerprints, individual test IDs, run IDs, raw trials, summary recomputation and exact HTML/JSON consistency are rechecked by `tools.audit_evidence`.
- Both test namespaces have zero remaining workers after each case, before subsequent tests or measurements. Final namespace/container cleanup, unchanged container-root firewall and stopped VM are verified.
- Installed package modules are compared with the validated checkout. Current records are in `reviews/mvp/` and `reviews/package-verification.json`.

`docs/MEASUREMENTS.md` reports the current run's endpoint medians/ranges, daemon VmHWM and state-directory allocation. Ten changing-policy trials are retained, split between five confirmations and five cancellations. TLS transport/checks/journal costs are included; Python command startup, preparatory status requests and the CLI confirm command's additional status fetch are excluded. RSS excludes nft children, clients and VM memory. No speedup, tail-latency, throughput, total-deployment-memory or production-SLA claim is made.

## Corrections in this final review

A malformed executor identity file previously escaped startup as JSON/type errors instead of producing the documented DEGRADED status. Recovery now bounds the record to 4 KiB, validates token/field types and refuses malformed data before any process lookup or signal. Production exposes DEGRADED and blocks new writes; it does not guess a PID or blindly restore over uncertain ownership. A portable regression and real TLS/Linux startup scenario cover this behavior. The regression failed before the correction, and a production mutation reintroducing the failure is caught.

The added corrupt-record fixture also exposed a cleanup gap: a parent process may already be dead while its owned group still contains an orphan. Fixture cleanup now retires owned groups regardless of parent status and verifies the known orphan exited. The runner prevents continuation to measurement with namespace workers remaining. The intermediate run is recorded as superseded and is not the source of published timing values.

Prior agent-assisted findings and their historical evidence are in [AGENT_REVIEW.md](AGENT_REVIEW.md); that review is not presented as an independent review of these later changes.

## Files and privacy

Current tracked contents and reachable Git-history blobs were inspected for unexpected binaries/large files, private keys, common GitHub/cloud credential formats, personal home paths and private contact addresses. No findings were observed. Git commit authors use the owner's GitHub noreply address. These checks are not a guarantee of detecting every possible secret format.

No virtual environment, raw host log, generated certificate/key, state database, toolchain download, VM disk, personal AGENTS/settings file or orchestration log is tracked. The structured test artifacts contain documentation-range addresses and test process identities; actual credentials are not retained. Runtime/build outputs remain ignored. No model/data asset or vendored runtime dependency was added.

## License and access

README and package metadata consistently have no selected project license; no LICENSE file or open-source grant was added. Third-party tools retain their own licenses as described in `THIRD_PARTY_NOTICES.md`; no image/binary redistribution or legal clearance is asserted.

GitHub was rechecked: Private, owner-only access, no pending collaborator invitations, read-only Actions tokens, no PR-approval permission, exact pinned-action allowlist and required SHA pinning, disabled external-fork workflows, and enabled Dependabot alerts/security fixes. See `reviews/security-settings.json`. The optional portable workflow remains manual-only; no remote CI pass is claimed.

Prior attempts to enable private main protection and Secret scanning were rejected by GitHub (403/422). Neither is described as enabled. Any future publication requires a separate license/visibility decision and rechecking/enabling available main and secret/push protection. No paid service or public visibility was enabled as a workaround.

## Remaining limitations

This remains a single-node IPv4 input-table MVP for the documented kernel/nft environment. A stopped agent has no running rollback timer. Whole-host reboot, power loss, systemd boot integration, arbitrary privileged writers, continuous connection-replacement attacks, other architectures and production qualification are not established by these results. Malformed metadata intentionally requires operator recovery, not automatic adoption.
