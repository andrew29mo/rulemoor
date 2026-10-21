# IPv6 preflight evidence review

Two read-only agents independently reviewed the production diagnostics/recovery path and the installed-service fixture/report evidence. No reproducible production admission, family-selection or rollback defect was found. The evidence review reproduced two gaps; agreement between reviewers is not a replacement for the checks below.

## Confirmed gaps and corrections

1. The verifier accepted partial/final confirmation projections with a shared unrelated boot, or a foreign-case partial projection from an unrelated operation. It checked selected fields without binding the full scenario. The verifier now requires the exact boot, operation ID, contiguous generation, phase, confirmed families and current/baseline/candidate policy for admitted, foreign, unknown, fresh-confirmation and recovery observations. The normal baseline commit before guard-denied restoration is exported and bound into that chain.
2. Foreign tables were read after plan and after the whole apply → partial-confirm → cancel sequence. A temporary change by apply that cancel reversed could evade those endpoints. The fixture now reads the real foreign table immediately before/after each of plan, apply, partial confirmation and cancel, for supported drops and the unknown-address scenario. The verifier requires all four ordered observations and each readback to match the original table.

Two portable regressions call the formal evidence helpers and reject mismatched identity/policy and intermediate changes even when the last readback matches. Eight additional corruption controls challenge wrong boot/op/generation/policy, intermediate known/unknown foreign writes, missing readbacks and an unrelated restoration baseline. These extend the evidence checks; they do not imply eight new production recovery capabilities.

## Reviewed production behavior

The formal evaluator selects the configured policy family, models relevant ip/ip6/inet input chains and preserves risk/unavailable for unknown or uninspectable conditions. IPv4 permission does not suppress IPv6 denial or uncertainty. Only an own-policy denial gates new admission. Cancel/deadline/startup reconciliation do not call the preflight guard; journal validity, known-policy checks and writer ownership still apply. Startup reconciliation precedes optional management-configuration loading.

The configured VM scenario uses the installed production wheel, service entrypoint, CLI TLS transport, Controller and nft backend. Same-listener probes distinguish IPv6 filtering timeouts from connection refusal and require IPv4 access and later IPv6 recovery. Old connections from both families are rejected; a new IPv4 receipt remains partial until fresh IPv6 confirmation commits. The three recovery modes restore both policies despite a baseline that would fail new admission.

## Scope

The review changes tests, VM observation and report checks, not the production runtime implementation. Full same-source native/container and actual-systemd validations are rerun after these executable changes; current identifiers and measurements are recorded in [deployment validation](DEPLOYMENT_VALIDATION.md), [operation measurements](MEASUREMENTS.md), [JSON](../reviews/deployment/deployment.json) and [HTML](../reviews/deployment/report.html). Older passing runs are historical, not reused as validation of the changed verifier.

Readbacks are per-operation endpoints, not continuous monitoring or protection against arbitrary privileged writers. Memory-backend tests do not prove kernel behavior. The VM uses static namespace-local peers. Configured-guard VM reboot, end-to-end WAN/NAT reachability, general IPv6 address/interface semantics, early-boot enforcement, uninterrupted connections and sudden power-loss recovery remain untested. Timing observations include documented control/probe overhead and are not recovery or capacity guarantees.

Retained source `5d2899bf453b3f6491afb0f7e9ebf52f70cf339035e205705985eb457af973ac`; native/container run `1344705fc9496855` (111 tests per platform, 32 production mutations); actual-systemd run `c6c726cffd12db8e` (15 groups, 65 evidence controls). HTML/JSON audited; fixture cleanup passed and VM stopped. Power-loss tested: false.
