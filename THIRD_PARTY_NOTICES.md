# Third-party tools and license status

Rulemoor's authored source currently has no selected license. This file does not grant an open-source license to that source. No model, external dataset, vendored Python library, binary toolchain, certificate or VM image is committed.

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

The local tool installer is adapted from the author's earlier tiny-event-relay tooling. There is no third-party model/data licensing scope for this project. Before public release, select a project license separately and recheck dependencies if the distribution contents change.
