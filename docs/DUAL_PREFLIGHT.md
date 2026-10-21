# IPv6 management preflight and read-only external diagnosis

This opt-in extension evaluates declared local TCP destination ports independently for IPv4 and IPv6. It is a conservative input-chain model, not a route, source-address or end-to-end reachability proof. New dual changes still require fresh TLS confirmations over both actual socket families.

## Configuration and results

Use the existing `serve --management-paths FILE` argument with a bounded JSON file:

```json
{"paths":[{"name":"api4","family":"ipv4","port":18443},{"name":"api6","family":"ipv6","port":18443},{"name":"ssh6","family":"ipv6","port":22}]}
```

See [the dual example](../examples/dual-management-paths.json). The total limit remains eight entries and 4 KiB. Names are globally unique; family/port pairs are unique. The same port may be declared once in each family. Omitted `family` retains the legacy IPv4 meaning; it does not silently cover both families. Unsupported family labels, extra address fields, duplicates and malformed files are refused. The policy itself still contains destination-port rules, not source-IP filtering.

Configured responses retain the aggregate `own_policy` and `external` results and add `family_statuses` for IPv4 and IPv6. Each family reports its configuration, own-policy and external status. An undeclared family is `not_configured`, never inferred safe. In dual mode, `ipv6_preflight` is `configured` or `not_configured`; it is no longer `not_implemented`. Declaring an IPv6 path against a legacy IPv4 policy yields own-policy `risk` / `unmanaged_family`, not `allowed`.

First-match/default evaluation uses the selected candidate family. A known own-policy drop in either declared family refuses a new apply before durable intent or kernel changes. IPv4 permission cannot override an IPv6 denial. Plan remains read-only. External blocked, risk and unavailable outcomes remain warnings, with per-family detail preserved; they do not authorize changing another manager's rules or prove that an apply can be confirmed.

## Foreign-rule model

The production reader remains a bounded, timed `nft -j -s list ruleset` command. Relevant `ip` chains apply to IPv4, `ip6` to IPv6, and `inet` to both with family-aware `meta nfproto` conditions. Rule order, exact TCP destination ports, TCP/UDP protocol checks and NEW/ESTABLISHED connection states retain the existing conservative semantics. Both owned tables are excluded only in explicit dual mode. A same-named IPv6 table is not silently treated as owned by a legacy IPv4 installation.

Unsupported IPv6 address/interface conditions, sets, jumps, unknown actions, other hooks and truncation remain uncertain. Risk in IPv6 remains visible even if IPv4 has no observed conflict. Inspection failure is unavailable, never clear. The existing 1 MiB output / two-second reader, 4096-entry and 64-chain budgets remain unchanged. There is no lock against other privileged writers; all results are point-in-time observations.

No diagnostic code modifies foreign rules. Only Rulemoor's owned table pair is replaced by its existing atomic nft batch. Required cancel, deadline and startup reconciliation bypass admission preflight: restoring a known baseline must still work even when new admission under the current configuration would reject it. Existing journal validation, drift refusal and writer retirement still apply; this is not permission to overwrite unknown policies.

## Validation and evidence boundary

Portable tests exercise formal parsing, per-family evaluation, own-policy rejection without journal/kernel mutation, family-aware ip6/inet analysis, unsupported conditions, inventory bounds and legacy compatibility. Controller tests use real SQLite with a memory backend and require cancel, deadline, process restart and synthetic changed-boot restoration despite a guard-blocked baseline. Local TLS tests verify configured IPv6 denial, explicit risk, old-connection rejection and separate fresh confirmations. Three added production mutations substitute IPv4 policy for IPv6, misclassify inet nfproto and omit IPv6 input chains; each must fail an assertion.

The installed-service VM adds a configured dual case on static veth peers. It checks IPv6 own-policy denial while IPv4 is allowed, foreign ip6 drops at priorities -100 and 10, an inet IPv6-only drop, same-listener IPv4 success / IPv6 timeout and reconnect after removing the fixture rule, unknown IPv6 source matching retained as risk, and exact foreign-rule preservation across plan/apply/cancel. Configured old IPv4/IPv6 TLS connections are rejected and fresh confirmations commit only after both families. Cancel, deadline and SIGKILL/service restart must restore both baseline policies even though the configured probe ports make that baseline inadmissible as a new change. Listener, temporary configuration and foreign-table cleanup are required.

The report requires these raw receipts and challenges them with six added corruption controls, including IPv4 masking IPv6, false certainty, foreign-rule writes, TCP refusal masquerading as filtering, missed restoration and one-family commit. Timed configured plan observations include client/namespace/TLS overhead. Agent RSS/VmHWM and cgroup memory are separate from VM RAM; no performance improvement or capacity bound is inferred.

Actual configured-guard VM reboot, WAN/NAT reachability, IPv6 address/interface semantic modeling, routed PMTU, SLAAC/RA security, arbitrary firewall compatibility, continuous attacks, early-boot protection, uninterrupted existing connections and sudden power-loss recovery remain untested. Existing separate dual VM boot evidence does not turn this configured scenario into a configured-guard reboot test.

[Deployment method and measurements](DEPLOYMENT_VALIDATION.md) · [JSON](../reviews/deployment/deployment.json) · [HTML](../reviews/deployment/report.html)

Retained source `a0c093c5ee46f8a93d23f7ffb4bcb280c2a0cdc47de8803b6ba5cb9bc77f76ac`; native/container run `ef8a435b0ccead85` (109 tests per platform, 32 production mutations); actual-systemd run `9d88cdff84bdc2e6` (15 groups, 57 report controls). JSON/HTML audited; VM stopped and fixture cleanup passed. Power-loss tested: false.
