# VFIO PCI device assignment

libkrun can cold-plug Linux PCI functions into an x86_64 guest with the VFIO
cdev and IOMMUFD kernel APIs. Build the selected library variant with `VFIO=1`
and pass one already-open `/dev/vfio/devices/vfioN` descriptor per function to
`krun_add_vfio_device` before starting the VM.

```c
int fd = open("/dev/vfio/devices/vfio42", O_RDWR | O_CLOEXEC);
if (fd < 0)
    /* handle errno */;

/* Expose the function as 0000:00:01.0 in the guest. */
int ret = krun_add_vfio_device(ctx_id, fd, 1, 0);
close(fd); /* libkrun retained its own duplicate */
if (ret < 0)
    /* handle -ret as errno */;
```

The host must provide `/dev/iommu`, VFIO cdev support, and a VFIO PCI variant
driver. The caller is responsible for binding every function it assigns and
for ensuring that every device in the effective IOMMU isolation group is
assigned together or detached from host drivers. Use each function's
`vfio-dev` sysfs entry to resolve the exact cdev; cdev numbers are not stable
identifiers.

The current boundary deliberately supports:

- PCI mechanism #1 on guest bus 0, with explicit device/function placement.
- Fixed 32-bit and 64-bit memory BAR assignment, including very large 64-bit
  BARs.
- MSI-X delivery through KVM and device reset at attach and teardown.
- One IOMMUFD IOAS for the VM with identity IOVA-to-GPA mappings.
- Confidential-guest DMA only to pages that the guest converted to shared
  state. Ordinary guests map all RAM at startup.

It does not currently implement hot plug, migration, I/O BARs, MSI, or INTx.
Guest drivers for assigned devices therefore need usable MSI-X capabilities.

## Confidential-computing boundary

VFIO assignment and IOMMU isolation are necessary plumbing, not proof that a
device belongs to the confidential VM. This API does not by itself establish
PCIe IDE encryption, TDISP assignment, device firmware identity, GPU protected
mode, or encrypted GPU-to-GPU links. A relying party must verify those claims
from CPU, device, and topology evidence tied to the same launch policy.

For accelerator configurations such as NVIDIA B200, the guest and vendor
driver stack must establish the protected-device session and collect signed
GPU evidence. An eight-GPU system must additionally attest every GPU and the
NVSwitch/NVLink topology; a successful VM quote alone is insufficient. libkrun
fails closed on confidential DMA by leaving all pages unmapped until the guest
explicitly shares them, but hardware-backed validation still requires the
target platform.

## Build combinations

```sh
make VFIO=1
make SEV=1 VFIO=1
make TDX=1 VFIO=1
```

`krun_has_feature(KRUN_FEATURE_VFIO)` reports whether the running library has
the supported Linux x86_64 VFIO boundary. Other targets retain the API symbol
and return `ENOTSUP` from `krun_add_vfio_device`.
