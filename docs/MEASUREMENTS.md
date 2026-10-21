# Observed MVP measurements

Retained run: `6ed204f4e6c8dead`. Executable snapshot: `ac398e4379e004285a44459268cd555940bee5b0cf898ba5b47315f723729e8d`.

Environment: Linux 6.8.0-117-generic/aarch64, Python 3.12.14, nftables 1.0.6, inside a Colima VM. Container limits: 2 vCPU, 768 MiB. No native macOS agent-performance claim.

| Operation | Trials | Median ms | Minimum–maximum ms |
|---|---:|---:|---:|
| plan | 10 | 11.63 | 8.27–16.15 |
| apply | 10 | 46.18 | 41.45–50.80 |
| confirm | 5 | 3.79 | 3.67–4.69 |
| cancel | 5 | 30.81 | 29.46–32.14 |

Each timed operation includes a fresh TLS connection, request/response and its relevant kernel checks and FULL-sync journal work. Client Python startup and the status fetch used to prepare each trial are outside the timer. Confirm timing uses the payload returned by apply; it does not include the extra status fetch performed by the interactive CLI confirm subcommand. These are endpoint round trips through the production CLI transport, not complete command-launch timings. One sequential client alternates between two one-rule policies, so every application changes the rule. Five operations are confirmed, five cancelled. Service readiness is the only warmup; every trial is retained. Ten samples are exploratory, not a tail-latency or throughput characterization. No competing-product baseline, speedup or production SLA is claimed.

Agent initial RSS: 22.84 MiB; final RSS and kernel VmHWM: 23.54 MiB / 23.54 MiB. This excludes transient nft children, client processes, container services and the VM. It is not total deployment memory.

State directory after ten trials: 347,881 logical bytes, 372,736 allocated bytes (364 KiB). Includes the 256 KiB reserve and test TLS material. It excludes the container image, VM disk and Python installation; it is not a deployment-size claim.

In one management-loss test with a 3-second window, rollback started 42.9 ms after the deadline and rule restoration was verified 91.3 ms after it. A subsequent fresh management request succeeded. Reachability-completion delay was not separately timestamped. These are single-run observations, not recovery-time upper bounds.

Native macOS and Linux each passed 85 tests on the same source snapshot. Twenty-five production mutations and seventeen evidence-corruption controls were rejected. Real-kernel cases additionally cover six crash boundaries, two foreign-policy cases, backlog and response-loss scenarios, real executor timeout and actual bounded-tmpfs ENOSPC. macOS test-process peak RSS is retained for provenance only, and must not be compared to Linux daemon VmHWM.

[Raw records](../reviews/mvp/combined.json) · [HTML report](../reviews/mvp/report.html)

The added slow-client test uses the default 5-second absolute connection lifetime with sixteen finite, unauthenticated TLS connections. It observes rollback while all slots are occupied and successful fresh confirmation after the slots recover. It does not establish availability under continuous replacement connections. Measurements above are a new run of the reviewed implementation; differences from older runs are not presented as improvements or regressions.

The current regression run checks that both test namespaces have no remaining workers after each case, before the next case or measurement. Corrupt executor metadata is a refused-recovery diagnostic case: production reports DEGRADED and blocks changes; the fixture then retires its known orphan.

This retained run includes the new-boot recovery implementation and its regressions. The container operation workload is unchanged; timing differences between runs are not evidence of a performance change. Separate actual-systemd/VM restart observations are in [DEPLOYMENT_VALIDATION.md](DEPLOYMENT_VALIDATION.md).

This operation benchmark has no management-path configuration: its diagnostics explicitly say not_configured, and no global inventory is read. Configured installed-service plan observations include CLI startup/namespace overhead and are reported separately in deployment validation. They are not a paired overhead comparison.
