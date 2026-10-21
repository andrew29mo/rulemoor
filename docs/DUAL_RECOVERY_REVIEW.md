# Dual VM recovery evidence review

Two read-only agents independently examined the recovery implementation and the retained evidence/report paths. The main agent reconciled their findings against source and actual checks. Agent agreement is not a substitute for test evidence.

## Findings and corrections

- The generated HTML still said dual-stack VM boot was untested, immediately before reporting a successful partial-confirmation dual boot. The renderer now distinguishes that original static-peer case from the separately reported boot case; committed-only dual boot remains untested. An existing report regression now renders both cases together and rejects the old wording. Running that assertion against the previous renderer fails as expected.
- Older current-sounding validation paragraphs still said two restarts, twenty-six evidence controls and no dual boot evidence. They now describe three restarts, fifty-one controls and the precise partially confirmed dual case.
- The recovery method said rules were unchanged throughout the late-release observation. Actual readbacks bracket the wait. The method now says before/after readbacks and explicitly excludes continuous observation.

## Recovery invariants reviewed

The stopped service must leave the partial-confirmation journal and both candidate tables intact. On a changed boot, the namespace dependency reads the identical pending journal before the Agent starts and observes both owned tables absent. Installed production startup must restore both canonical baseline tables; fresh IPv4 and IPv6 TLS probes agree with that state. This excludes a rollback completed during shutdown being counted as boot recovery.

The held executor is deliberately outside the service cgroup. It must remain the same live process after its temporary Agent is killed and hold the actual writer lock. Production startup retires that identity before acquiring writer ownership and admitting a distinct successor. Stale operations are rejected with immediate journal/two-table readbacks. Releasing the already retired intent must leave the successor unchanged at the later readback. This verifies retirement, not safe execution by a live obsolete writer.

Portable recovery tests call production Controller and real SQLite; their memory backend isolates state-machine contracts and cannot establish kernel or pidfd behavior. Actual installed-service VM checks supply those observations. The runtime Controller/backend/executor were unchanged by this review; only report generation, an assertion and documentation changed.

## Evidence and limits

The same-source native/container and actual-systemd suites were rerun after the executable report/test changes. The retained run identifiers, exact source fingerprint, measurements and required cleanup are recorded in [deployment validation](DEPLOYMENT_VALIDATION.md), [operation measurements](MEASUREMENTS.md) and their linked JSON/HTML. Auditors require exact generated HTML/JSON agreement. Older attempts remain explicitly historical.

The distinct recovery policies use redundant drop markers under default-drop, so full canonical readback proves exact two-family rule preservation; fresh TLS covers the management path. This is not broad data-plane equivalence. The VM reboot is orderly stop/start, not abrupt power loss. Committed-only dual boot, other executor/kernel boundaries, arbitrary privileged writers and uninterrupted or fail-closed early boot remain untested. Two endpoint readbacks do not establish continuous immutability, and timing observations are not service-level bounds.

Historical review source `6165ed1aca054e8ece3a93c7a1e348e540424f1a855ab698129147539d0cb3b7`; native/container run `7b1479d07fdd3012`; actual-systemd run `71eba3fbcb9238fb`. 102 tests per platform, 29 production mutations, 14 deployment groups and 51 evidence controls passed. VM final state: Stopped. Power-loss tested: false.
