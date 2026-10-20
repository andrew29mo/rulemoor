# Third-party tools and licenses

Rulemoor's authored source and documentation are licensed under MIT; see [LICENSE](LICENSE). That grant does not relicense third-party components. No model, external dataset, vendored Python library, binary toolchain, certificate or VM image is committed.

Runtime Python imports are from the standard library. Building a distribution uses setuptools. Testing/provisioning uses external tools with their own licenses:

| Component | Role | Upstream license/reference |
|---|---|---|
| Python | Runtime/standard library | [Python license](https://docs.python.org/3/license.html) |
| setuptools | Package build backend | [MIT](https://github.com/pypa/setuptools/blob/main/LICENSE) |
| nftables/libnftables | Separate system executable/library | [GPLv2, upstream licensing](https://git.netfilter.org/nftables/tree/COPYING) |
| iproute2 | Linux test topology | [Upstream COPYING](https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/COPYING) |
| OpenSSL | Test TLS certificates/system TLS | [Apache-2.0](https://openssl-library.org/source/license/) for the retained Linux OpenSSL 3 build; host versions can differ |
| Colima | Local VM orchestration | [MIT](https://github.com/abiosoft/colima/blob/main/LICENSE) |
| Lima | Local Linux VM | [Apache-2.0](https://github.com/lima-vm/lima/blob/master/LICENSE) |
| Docker CLI / buildx | External container tooling | [Docker CLI](https://github.com/docker/cli/blob/master/LICENSE), [buildx](https://github.com/docker/buildx/blob/master/LICENSE), Apache-2.0; Docker Desktop has separate distribution terms |
| actions/checkout, actions/setup-python | Optional remote workflow | [checkout MIT](https://github.com/actions/checkout/blob/main/LICENSE), [setup-python MIT](https://github.com/actions/setup-python/blob/main/LICENSE) |

The validation Dockerfile assembles an upstream Python/Debian image with Debian packages. Package dependencies and their notices remain in the resulting image; the image itself is not uploaded with this repository. No claim is made that all image packages share one license. Redistributing an image or binary bundle would require a separate distribution/license review.

The local tool installer is adapted from the author's earlier tiny-event-relay tooling. There is no third-party model/data licensing scope for this project. Recheck dependencies and distribution obligations if the distribution contents change.

## MIT adoption review — 2026-10-21

The tracked repository contains authored Python source, tests, configuration, documentation and structured validation records. Its Python runtime dependencies are standard-library modules; `pyproject.toml` declares no third-party runtime packages. Setuptools is an external MIT-licensed build backend. The local installer is adapted from the same author's MIT-licensed tiny-event-relay project.

Production invokes `nft` as a separate subprocess using its command-line interface; it does not import nftables Python bindings, load libnftables, or incorporate nftables source. The retained Linux environment uses nftables/libnftables 1.0.6 and iproute2 as separately installed system packages. Their GPL and other package notices remain applicable to those components; Rulemoor's MIT license does not replace them. Upstream netfilter licensing information is also available at [netfilter licensing](https://www.netfilter.org/about.html#license).

The source repository and Python distributions do not bundle the VM, container image, nftables/iproute2 executables, Python/OpenSSL runtime or Docker tooling. Based on this source-only distribution and the observed subprocess boundary, no conflict requiring a different project license was identified. This conclusion does not cover a future combined binary, container or appliance distribution.

The wheel and source distribution include both `LICENSE` and this notice. Licensing grants do not change the repository's Private visibility.
