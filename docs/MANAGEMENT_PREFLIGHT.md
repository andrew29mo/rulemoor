# Management-port preflight and foreign firewall diagnostics

This opt-in feature protects explicitly declared **local IPv4 TCP destination ports at the input hook**. It evaluates NEW traffic against Rulemoor's candidate policy and reads the current namespace's nftables ruleset for potential external conflicts. It does not reconstruct the route from a client's socket, infer NAT/tunnel endpoints or establish end-to-end reachability.

## Enable and use

The existing unit/CLI behavior remains compatible. Without `--management-paths`, plan reports `not_configured`; no management-port admission guard or external inventory is enabled. This is deliberately visible, not a passing preflight.

Provision an administrator-controlled JSON file using [the example](../examples/management-paths.json):

```json
{"paths":[{"name":"rulemoor-api","port":18443},{"name":"ssh","port":22}]}
```

Use 1–8 unique names and unique ports; names contain 1–48 ASCII letters, digits, underscores or hyphens. Ports are integers 1–65535. An explicit null paths value, unknown fields, booleans as ports, duplicates, symlink configuration files and files over 4 KiB are rejected. Configuration is loaded at startup and copied; it is not client-controlled request data or a live-reload mechanism. Store it outside writable application/user directories. Changing it requires a reviewed service restart; inspect pending status first because graceful shutdown attempts rollback. Keep independent console access.

Append `--management-paths /etc/rulemoor/management-paths.json` to the installed agent's existing `serve` arguments, retaining its certificate, token, state, bind address and port. The sample systemd unit does not silently enable this opt-in configuration. A deployment override must preserve all existing sandbox/capability settings. Startup first reconciles the existing journal and owned policy, then loads this admission configuration before opening the API. A missing/invalid file prevents new API service, but does not skip that reconciliation. Repair the local file and reset/start the service if its restart limit has been reached. Other startup prerequisites, including a usable TLS key and storage, can still prevent recovery; provision and validate them before restarting.

The normal CLI `plan POLICY` prints JSON including `diagnostics`. When configured, a newly accepted `apply` also returns diagnostics observed before application. Unconfigured apply keeps its prior receipt shape; use plan to see `not_configured`. An own-policy conflict returns HTTP 409 with diagnostics; the CLI shows the rejection reason, and `plan` supplies the complete JSON. A deduplicated apply returns its retained receipt plus a new diagnostic snapshot marked `receipt_lookup_no_reapply`; it does not reapply or undo the original operation. Diagnostics are response data, not journal state or confirmation receipts.

Choose the local destination port after any translation into the input hook. A public 443-to-local-18443 mapping does not mean 443 is the correct protected local port. For SSH tunnels, separately declare the actual SSH management port where relevant. Names identify operator intent; the service does not verify that a listener exists or that it is the desired application.

## Admission and diagnosis are different

| Result | Meaning and behavior |
|---|---|
| Own policy `allowed` | Ordered first-match/default evaluation permits NEW TCP to every configured port. No reachability proof. |
| Own policy `blocked` | At least one configured port would be dropped by the candidate. A new apply is refused before journal/kernel mutation. Plan remains read-only. |
| `not_configured` | No declared management ports; this feature is not active. |
| External `blocked` | A supported foreign input-chain model drops NEW or ESTABLISHED TCP input at a declared local port. This is a conflict diagnosis, not a global packet-path proof. |
| External `risk` | Unsupported/conditional expressions, jumps, other hooks, unknown objects or a truncated inventory prevent a clear result. |
| External `no_observed_input_conflict` | No conflict was found within the supported input-chain model. It must not be read as “reachable” or “safe.” |
| External `unavailable` | Missing permission, command failure, timeout, excessive output or an unsupported response prevented inspection. No clear result is inferred. |

Only an own-policy `blocked` result gates new apply. External results are warnings and do not authorize modifying, adopting or overriding another manager's rules. This permits an operator to change Rulemoor's policy even when another tool currently blocks a path; fresh confirmation and timeout rollback remain mandatory. Preflight is not applied to startup recovery or rollback, which must not be blocked by a later management-configuration change.

The current established TLS socket is not sufficient: policy compilation still accepts established/related traffic first, while own-policy preflight models NEW traffic. External input-chain diagnostics evaluate NEW and ESTABLISHED packets separately: a fresh TCP/TLS session needs both, and allowing only NEW packets does not establish a conflict-free session. Confirmation still requires a fresh post-application TLS connection with the matching operation/generation/digest/challenge and an unexpired deadline. No request field bypasses the configured guard.

## External inspection model and budgets

Inspection executes only `nft -j -s list ruleset` in the agent's existing network namespace. It reads through bounded pipes with a 1 MiB accepted-output limit and a two-second read deadline; a final read chunk can exceed that limit before rejection. Failure cleanup kills and reaps the child in the tested process-failure cases. Hung kernel I/O is not tested. The evaluator accepts at most 4096 JSON entries and reports at most 64 input chains and 64 unassessed-hook entries; truncation is explicit. It never invokes a foreign-table mutation. The legacy compiler replaces only `ip rulemoor`; explicitly enabled dual mode replaces its owned ip/ip6 pair. Inspection never mutates foreign tables.

The evaluator follows rule order and terminal accept/drop/reject for supported exact TCP destination-port matches, TCP/UDP protocol checks, IPv4/IPv6 family checks and conntrack-state checks for NEW and ESTABLISHED ingress. A certain block of either modeled state is reported as blocked; otherwise an uncertain state remains risk. RELATED/INVALID/untracked packet behavior is not a complete connection simulation. It evaluates relevant `ip` and `inet` input base chains separately: another chain can drop a packet even after an earlier accept. Supported nonmatching rules are skipped. Unknown actions remain uncertain even if a later condition appears not to match, because an earlier action could rewrite that condition’s packet fields. Conditional addresses/interfaces, sets, jumps and other unsupported expressions remain uncertain rather than being assumed harmless. Counters/logging do not themselves create a verdict.

Rules and routes at other hooks, NAT, bridge behavior, legacy iptables, eBPF, external devices, IPv6 traffic and general application availability are outside the evaluated path. Other hooks and unknown objects observed in this namespace are flagged, not simulated. Overall risk takes precedence over a supported per-chain block when any such uncertainty is present; per-chain findings remain visible. Reports contain a point-in-time snapshot hash and bounded chain/path summaries, not the entire host ruleset or operator IP addresses. Those summaries can still reveal service/chain names; treat operational reports accordingly.

There is no lock excluding other privileged firewall writers. A fresh inspection is made for a new configured apply, but another manager can change its rules immediately afterward. Rulemoor never claims this inspection is atomic with external ownership or is an access guarantee.

[Agent-assisted review and corrections](PREFLIGHT_REVIEW.md)

## Validation evidence

Portable tests call the production configuration parser, diagnostic evaluator, bounded subprocess reader, Controller and real local TLS API. Synthetic rulesets exercise ordered/default policy, earlier/later chains, unknown conditions, jumps, absent configuration and resource failures; they are not kernel evidence.

The separate installed-service VM scenario configures the production entrypoint using a test-only argument override. It checks guard rejection without state/kernel mutation, starts a real TCP listener, creates disposable foreign chains before and after Rulemoor's priority, requires successful connects before each fixture drop, timeout while blocked and successful connects after removing only that fixture table, with unchanged live listener identity, compares foreign rules before/after diagnosis and an admitted change, and preserves old-versus-fresh TLS confirmation behavior. An address condition outside the supported model must remain `risk` even when the fixture's actual TCP attempt is blocked. Only the fixture creates/removes those foreign rules. Separate missing/null configuration trials SIGKILL a pending production service: the restarted entrypoint must restore the baseline before rejecting API startup, and local configuration repair/reset/start must restore service. These trials do not claim arbitrary startup failure recovery.

Current run IDs, source fingerprint, measurements and results are retained in [deployment validation](DEPLOYMENT_VALIDATION.md), [JSON](../reviews/deployment/deployment.json) and [HTML](../reviews/deployment/report.html). The configured plan intervals include CLI-process/namespace overhead and use different fixture conditions; they are not isolated diagnostic CPU cost or a speed comparison with the unconfigured operation benchmark. Agent memory comes from the stable configured service invocation, separate from VM RAM.

These are namespace-local Linux VM observations. No WAN/NAT/bridge/legacy-firewall compatibility, every firewall product, production availability, power-loss, native segmentation-fault or hung-I/O recovery is established.



## Dual-mode limitation

The [dual-stack slice](DUAL_STACK.md) does not extend this evaluator to IPv6. It evaluates only the IPv4 policy component and explicitly emits ipv6_preflight: not_implemented. Separate fresh IPv6 confirmation and common-deadline rollback are required; an IPv4 diagnostic must not be read as a passing IPv6 preflight.

Retained source `2173a5bb28d7610399e9d5479fb68e24d0eff6bf26c28fd84fc22acef8a4bb99`: native/container run `6b3e22b361d2e101` (96 tests per platform, 28 production mutations); installed-service run `6e80d14cf5601c9f` (11 groups, 37 report controls). The initial foreign-fixture syntax failure is disclosed in attempt history; it is not a complete pass.
