# TSI control reply fault tests

Build an instrumented host library from the repository root:

```sh
make debug FEATURE_FLAGS='--features ffi,devices/tsi-fault-injection'
```

Use that library with a matching TSIv4 guest kernel. The optional feature is
disabled by default and adds no exported API. The injector, diagnostic endpoint,
and extra queue state are absent from ordinary builds. Its state belongs to the
individual VSOCK device. This is a functional test build, not a performance build.

Build `tools/testing/selftests/net/tsi_control_fault` in the Linux tree and run it
inside the guest. Start Linux's `tsi_udp_server` on the VMM host and pass the four
printed comma-separated ports through `TSI_UDP_PORTS` to the guest test. Disable
automatic INET hijacking for the explicit TSI/native VSOCK tests. Host INET
impersonation and automatic publication must be enabled; use no restrictive port
map. Run once with default TCP publication and once with
`FAIL_ON_TCP_PUBLICATION_ERROR`. No firmware rebuild is needed for these tests
when the existing host/guest pair already implements the current TSIv4 ABI.

The test skips when the diagnostic endpoint is unavailable. Validation with the
instrumented library must require zero skips, a successful guest test result,
and no kernel sanitizer/locking diagnostics. A successful VMM exit alone is
insufficient evidence that the tests ran.

The suite covers malformed envelopes and results, incorrect sources and IDs,
duplicate replies, dropped replies, and replies held across interruption,
timeout, and socket replacement. A poisoned stale reply carries `-EACCES`, so
accepting it cannot accidentally look like a successful current operation.
Read-only queries must recover; uncertain state changes must require close.
Host proxy counts check cleanup, including failed creation. Replacement tests
reuse the guest listening address where applicable. Nonblocking TCP connect is
also covered. The 67 cases include ordinary-signal deferral and fatal-signal termination for
both metadata operations, plus 64 malformed-read/close/replacement cycles with
stale replies. The signal test first holds a valid reply, delivers SIGUSR1,
verifies the read is still waiting, then releases the reply. This does not inject
host process death, transport disconnection, or loss of one-way RELEASE requests.

## Portable HVF/KVM runner

The libkrun integration runner also contains `tsi-control-wire` and
`tsi-control-faults`. They cross-compile with the guest agent and run against
the existing matching firmware, without a Linux source checkout or a container
rootfs. For the instrumented dynamically linked run:

```sh
make test FFI=1 GPU=0 \
    FEATURE_FLAGS='--features ffi,devices/tsi-fault-injection' \
    KRUN_TEST_TSI_FAULTS=1 TEST=tsi-control-faults
```

On macOS add `EXTRA_LIBPATH_Darwin=/path/to/built/libkrunfw`. Repeat with
`KRUN_TEST_TSI_TCP_PUBLICATION_STRICT=1`. The explicit opt-in prevents ordinary
test runs from reporting a missing diagnostic endpoint as a successful check.

The portable fault case exercises GETNAME and SO_ERROR/GETOPT reply validation,
wrong source/ID filtering, duplicates, five-second dropped-reply deadlines and
subsequent recovery. Each metadata operation performs 64 malformed-read,
close/replacement cycles with a poisoned stale reply, ordinary-signal deferral
and fatal-signal termination. Malformed CREATE, SETOPT and LISTEN replies check
uncertain state, close-time cleanup and invalid LISTEN policy flags. These are
separate portable checks of the named behaviors; their results do not reproduce
the complete Linux kernel selftest matrix above. The instrumented run must
execute with no skips.

## Diagnostic protocol (test builds only)

Guest VSOCK datagrams to host CID 2, port `0x54534946`, configure the injector.
This separate test protocol is version 1; it is not part of the TSIv4 ABI.
Requests are exactly four little-endian u32 fields:

| Field | Meaning |
| --- | --- |
| version | 1 |
| operation | TSI reply operation/port to target |
| fault | Fault number below; zero queries counters without changing the plan |
| skip | Number of matching replies to pass before injecting once |

Replies are five little-endian u32 fields: version, positive status errno
(zero on success), matching reply count, injection event count, and current host
proxy count. Configuring a plan resets its counters and discards any previously
held reply. Querying leaves all state intact. The acknowledgement uses the same
diagnostic source port and is never itself injected.

| Fault | Effect |
| --- | --- |
| 1–3 | Wrong version, operation, or reply flags |
| 4–7 | Short header, short body, trailing byte, or wrong declared body length |
| 8–10 | Positive result, errno below -4095, or oversized reply |
| 11–13 | Wrong ID, source port, or source CID before the correct reply |
| 14 | Correct reply followed by an error duplicate with its old ID |
| 15 | Drop the selected reply |
| 16 | Hold until the next matching reply, then replay before it |
| 17–19 | Reserved LISTEN flag, invalid address length, or wrong address family |
| 20–22 | Only a wrong-ID, wrong-port, or wrong-CID reply; omit the correct reply |
| 23 | Release a held valid reply immediately; operation/skip must be zero |
| 24 | Send a bad-version copy now and retain the original for later replay; operation/skip must be zero |

Fault 16 retargets the saved reply to the next matching reply's destination port,
while preserving the saved request ID. This deterministically models a private
control port being reused; it does not claim the guest allocator wrapped around.
The replay also carries `-EACCES`. Holding and replaying count as two injection
events. A dropped reply counts as one. Other mutations count as one, including
a duplicate or an unrelated reply followed by the correct reply.

Injection happens after the native operation and before its reply enters the
guest RX queue, through the common synchronous/asynchronous response path.
Normal packet serialization still builds each reply before it is mutated.
