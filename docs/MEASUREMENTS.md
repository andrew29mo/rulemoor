# Observed MVP measurements

Retained run: `90a6c11375432d5f`. Executable snapshot: `cb4d5bc79e73366773b235b91fbf80e567bd08359c1e6f345fcbcdf715e5ed7d`.

Environment: Linux 6.8.0-117-generic/aarch64, Python 3.12.14, nftables 1.0.6, inside a Colima VM. Container limits: 2 vCPU, 768 MiB. No native macOS agent-performance claim.

| Operation | Trials | Median ms | Minimum–maximum ms |
|---|---:|---:|---:|
| plan | 10 | 12.39 | 8.12–18.73 |
| apply | 10 | 47.44 | 43.07–56.52 |
| confirm | 5 | 3.67 | 3.42–4.53 |
| cancel | 5 | 31.56 | 30.03–33.33 |

Each timed operation includes a fresh TLS connection, request/response and its relevant kernel checks and FULL-sync journal work. Client Python startup is outside the timer. One sequential client alternates between two one-rule policies, so every application changes the rule. Five operations are confirmed, five cancelled. Service readiness is the only warmup; every trial is retained. Ten samples are exploratory, not a tail-latency or throughput characterization. No competing-product baseline, speedup or production SLA is claimed.

Agent initial RSS: 22.76 MiB; final RSS and kernel VmHWM: 23.11 MiB / 23.11 MiB. This excludes transient nft children, client processes, container services and the VM. It is not total deployment memory.

State directory after ten trials: 347,881 logical bytes, 372,736 allocated bytes (364 KiB). Includes the 256 KiB reserve and test TLS material. It excludes the container image, VM disk and Python installation; it is not a deployment-size claim.

In one management-loss test with a 3-second window, rollback started 53.0 ms after the deadline and rule restoration was verified 100.3 ms after it. A subsequent fresh management request succeeded. Reachability-completion delay was not separately timestamped. These are single-run observations, not recovery-time upper bounds.

Native macOS and Linux each passed 41 tests on the same source snapshot. Five production mutations and five evidence-corruption controls were rejected. Real-kernel cases additionally cover six crash boundaries, two foreign-policy cases, backlog and response-loss scenarios, real executor timeout and actual bounded-tmpfs ENOSPC. macOS test-process peak RSS is retained for provenance only, and must not be compared to Linux daemon VmHWM.

[Raw records](../reviews/mvp/combined.json) · [HTML report](../reviews/mvp/report.html)
