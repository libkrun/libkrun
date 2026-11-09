# End-to-end tests
The testing framework here allows you to write code to configure libkrun (using the public API) and run some specific code in the guest.

## Running the tests:
The tests can be run using `make test` (from the main libkrun directory).
You can also run `./run.sh` inside the `tests` directory. It uses static linking by default. To test the shared libraries directly on Linux, build the local prefix and set the library paths from inside `tests/`:

```bash
make test-prefix                 # from the repository root
cd tests
KRUN_TEST_FFI=1 \
  PKG_CONFIG_PATH="$(realpath ../test-prefix/lib64/pkgconfig)" \
  LIBKRUN_LIB_PATH="$(realpath ../test-prefix/lib64)" \
  ./run.sh test
```

The paired Linux control reply fault suite uses an opt-in instrumented host
build; see [TSI control reply fault tests](../docs/tsi-control-faults.md).

## TSI application compatibility

Run the stock-application cases against a matching TSIv4 / libkrunfw ABI 6 kernel:

```sh
make test FFI=0 TEST='tsi-app-*'
```

Add `KRUN_TEST_TSI_TCP_PUBLICATION_STRICT=1` to run the same batch with
`FAIL_ON_TCP_PUBLICATION_ERROR` enabled. For example:

```sh
KRUN_TEST_TSI_TCP_PUBLICATION_STRICT=1 make test FFI=0 TEST='tsi-app-*'
```

This verifies ordinary application behavior with available host ports in both
policies. Focused guest tests separately cover occupied-port fallback/failure
and retry, including TCP port overrides. Use the matching TSIv4 firmware with
the eight-byte LISTEN reply.

The twenty-eight cases run curl HTTP/HTTPS, two parallel curl scenarios, wget HTTP,
dig over UDP/TCP, dnsmasq, OpenSSL DTLS, iputils ping, and `python3 -m http.server` over both IPv4
and IPv6. Existing names select IPv4; their `-ipv6` counterparts select IPv6.
Use `TEST='tsi-app-*-ipv6'` to run just IPv6. The Python server is reached
from both the host through a port mapping and a guest-local curl client.
Applications use their normal socket settings. The guest verifies that automatic INET hijacking is
active and no `eth0` device exists; no virtual NIC is added.

`tsi-app-ping` and `tsi-app-ping-ipv6` require a Linux host and run the installed
iputils binary with ICMP datagram sockets, not UDP echo or raw ICMP. Each checks
ordinary ping, `-C` and an explicit nonzero `-e` identifier against both a
host-only target and guest loopback. Every invocation must receive all three
replies with nonzero TTL/hop-limit metadata. The child runs as UID/GID 65534
with `no_new_privs`, preventing raw-socket privileges from masking a regression.
The guest enables `ping_group_range`; the host fixture permits its mapped group
0 and assigns the target IP only inside the runner's private network namespace.
The normal runner sets `KRUN_TEST_PRIVATE_NETNS=1` after entering that namespace.
If running a custom namespace wrapper with `KRUN_NO_UNSHARE=1`, set that marker
inside the private namespace too; the fixture refuses to configure the real
host namespace. A supplied offline rootfs must include iputils `ping`.

The two parallel curl cases require a Linux host and skip on macOS. A saturated
host TCP accept queue holds one connection pending while another transfer must
finish. The delayed case then opens the queue and checks both response bodies;
the timeout case keeps it closed and verifies curl's one-second connection
timeout fires within 2.5 seconds. The fast body must arrive before opening the
slow queue in both cases. Use `TEST='tsi-app-curl-parallel-*'` to select them.

`tsi-app-openssl-dtls` runs the installed `openssl s_server -dtls1_2` as an
incoming UDP service. An unmodified host `openssl s_client` verifies the test
certificate and exchanges plaintext through an explicit UDP port mapping;
a guest-local client repeats the exchange after restarting the server. This
checks incoming UDP before an application send, replies, guest-local delivery,
and close/rebind in each address family. Applications use normal socket settings.

`tsi-app-dig-udp-large` checks a UDP reply larger than 3 KB containing 192
separate A records, with TCP retry disabled. `tsi-app-dig-udp-fallback` checks
that a truncated UDP response makes stock dig retry automatically over TCP;
the fixture verifies both transports were used. Both have `-ipv6` counterparts.

`tsi-app-dnsmasq` and `tsi-app-dnsmasq-ipv6` run stock dnsmasq with a fixed
loopback listener and local DNS data. Sixteen simultaneous host dig processes
query its mapped UDP port, and a host TCP query and guest-local UDP/TCP queries
verify the same answer. UDP clients disable TCP retry. This exercises incoming
UDP before any application send and replies to multiple independent peers.
The IPv6 case requires guest packet-info support for explicitly bound addresses.
The wildcard cases below add destination metadata and source selection coverage.
Interface-only source routing and scoped IPv6 remain outside that coverage.

`tsi-app-dnsmasq-wildcard` and its `-ipv6` counterpart omit `--bind-interfaces`
and use ordinary wildcard sockets filtered to guest loopback. Sixteen host UDP
clients query the service, followed by a host TCP query; guest-local UDP/TCP
clients verify native delivery. Clients bind to the primary loopback address
so replies from an incorrect default source are detectable. Linux IPv4 uses
both `127.0.0.1` and `127.0.0.2`; the alternate can be overridden with
`KRUN_TEST_TSI_IPV4_ALTERNATE`. Other hosts default to one IPv4 address.
Set `KRUN_TEST_TSI_IPV6_ALTERNATE` to another address already assigned to the
host to check distinct IPv6 destinations as well. The tests do not configure
host interfaces. These cases require the coordinated 168-byte TSIv4 datagram
header and support for source selection on proxy sends.

Local host fixtures use ephemeral ports and fixed test data. HTTPS verifies a
locally generated certificate through an explicit test CA and verifies the
selected loopback IP address. IPv6 tests use literal `::1` addresses, including
URL brackets, so they cannot fall back to IPv4. Tests require no
public network service at runtime. Application versions, commands and failures
are recorded in the per-case logs. Host `openssl` and `dig` are needed for the
TLS/DTLS and incoming DNS fixtures.

By default the existing Podman rootfs provisioner builds a Fedora 43 image with
curl, wget, Python, bind-utils, OpenSSL and dnsmasq. Check the runner summary for skips
if image provisioning is unavailable. To use an existing rootfs offline:

```sh
KRUN_TEST_TSI_APPS_ROOTFS=/path/to/application-rootfs \
    make test FFI=0 TEST='tsi-app-*'
```

That rootfs must contain the stock `curl`, `wget`, `dig`, `openssl`, `python3`
and `dnsmasq` commands in `/usr/bin`, `/usr/sbin`, `/bin` or `/sbin`, plus their
loader, libraries and Python standard library. dnsmasq uses the root account
from the rootfs passwd/group files to avoid requiring a service account.
It is copied into each test's private root before init/fixture files are added;
the supplied rootfs is not modified. Use `TEST_FLAGS='--base-dir /path/to/results'`
when you need to choose storage for the copies. Passing these cases establishes
coverage for the recorded application versions and IPv4/IPv6 paths, including
parallel progress, connection deadlines, large/truncated DNS replies and
incoming TCP, DNS and UDP/DTLS. These
fixtures do not cover arbitrary routed topologies, link-local scope IDs or
every UDP service; broader service compatibility remains an additional target.

## Running on macOS

### Prerequisites

1. Install required build tools:
   ```bash
   brew install lld xz
   rustup target add aarch64-unknown-linux-musl
   ```

2. Install libkrunfw from the [libkrun Homebrew tap](https://github.com/libkrun/homebrew-krun):
   ```bash
   brew tap libkrun/krun
   brew trust libkrun/krun
   brew install libkrunfw
   ```

   For a source build, follow the [libkrunfw macOS instructions](https://github.com/libkrun/libkrunfw#macos), then run `make test LIBKRUNFW_SRC=/path/to/libkrunfw` to install that firmware into `test-prefix/` for the tests.

   `make test` includes the Homebrew libkrunfw path automatically.

### Running tests

```bash
make test
```

## Adding tests
To add a test, add a Rust module under `tests/test_cases/src/`, implement the required host and guest methods (see existing tests), and register it in `tests/test_cases/src/lib.rs`.

## FreeBSD guest tests

FreeBSD guest tests run on Linux (amd64, arm64) and macOS (arm64) hosts. They require two external assets that are not bundled in the repository.

### Prerequisites

1. Install required tools:
   - **macOS**: `bsdtar` is built-in (`/usr/bin/bsdtar`)
   - **Linux**: `sudo apt-get install libarchive-tools` (provides `bsdtar`)
   - **Linux/macOS amd64**: add the Rust cross-compilation target:
     ```bash
     rustup target add x86_64-unknown-freebsd
     ```
   - **Linux/macOS arm64**: `aarch64-unknown-freebsd` has no prebuilt stdlib in rustup,
     so a nightly toolchain with rust-src component is needed:
     ```bash
     rustup +nightly-2026-01-25 component add rust-src
     ```

2. Build the FreeBSD sysroot and `init-freebsd` (from the libkrun root directory):
   ```bash
   make BUILD_BSD_INIT=1 -- init/init-binary/init-freebsd
   ```
   This downloads `freebsd-sysroot/base.txz`, extracts it to `freebsd-sysroot/`, and compiles `init/init-binary/init-freebsd`.

3. The FreeBSD kernel is downloaded and cached automatically by `run.sh` (from
   a Firecracker-optimized release on x86_64 or `download.freebsd.org` on aarch64). To use a locally provided kernel instead, set
   `KRUN_TEST_FREEBSD_KERNEL_PATH` before running:
   ```bash
   export KRUN_TEST_FREEBSD_KERNEL_PATH="/path/to/boot/kernel/kernel"      # amd64
   export KRUN_TEST_FREEBSD_KERNEL_PATH="/path/to/boot/kernel/kernel.bin"  # arm64
   ```

### Running FreeBSD tests

With the sysroot/init assets built, `run.sh` (or `make test`) will automatically:
- Cache the x86_64 kernel at `target/freebsd-kernel/freebsd-kern.bin` or the aarch64 kernel at `target/freebsd-kernel/boot/kernel/kernel.bin`
- Cross-compile the `guest-agent` for FreeBSD
- Build `target/freebsd-test-rootfs.iso` from `init-freebsd` + the FreeBSD `guest-agent`
- Set `KRUN_TEST_FREEBSD_KERNEL_PATH` and `KRUN_TEST_FREEBSD_ISO_PATH` for the runner

FreeBSD tests are **skipped** (not failed) when the kernel or ISO are unavailable, so the test suite still passes without FreeBSD assets.
