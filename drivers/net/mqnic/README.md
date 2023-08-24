# DPDK PMD driver for the corundum project

This driver was tested with a 10G version of mqnic build for an AMD ZCU106 board. It was attached to a standard intel
NIC (X710 based). Both hosts were running Ubuntu 18.04 with the intel NIC being operated using the standard Linux driver
and the mqnic being operated by this new DPDK PMD.

Using a packet generator like pktgen and tcpdump on the intel NIC side, this driver has been validated, while the mqnic
side was running either the "dpdk-testpmd" or "l2fwd" example applications with no-mac-updating option enabled.

This driver is built against

- DPDK-Stable 20.11 [1] as a base for the DPDK driver
- a specific, partially outdated Corundum/mqnic version [2]
  as the base for the mqnic adapted from the kernel driver
  and for the hardware design
    - [1] http://git.dpdk.org/dpdk-stable/commit/?h=20.11&id=ece54855816f1d03ef8ae08dedcb02318a97f3fb
    - [2] https://github.com/corundum/corundum/commit/56fe10f27d9b42f1ff9abe4d735b113008e4be9d

## How to build

### Prerequisites

To prepare a DPDK pmd for usage, the following commands shall be executed. Especially note that hugepages have to be
enabled when using a DPDK pmd.

```shell
sudo ./usertools/dpdk-hugepages.py --setup 2G
sudo modprobe vfio-pci
sudo ./usertools/dpdk-devbind.py -b vfio-pci 0000:06:00.0
```

### Building the DPDK project

The following commands must be executed in the project root directory:

```shell
meson -Dexamples=all build
ninja -C build -j"$(nproc)"
```

## Testing

### l2fwd

The [l2fwd](https://doc.dpdk.org/guides-20.11/sample_app_ug/l2_forward_real_virtual.html) app from the dpdk project
forwards the incomming traffic to the next port as outgoing traffic. This driver was tested with the following command:

```shell
sudo ./build/examples/dpdk-l2fwd -l 0-3 -n 4 -- -p 0x3 --no-mac-updating
```

The output should look similar to the following log:

```
$ sudo ./build/examples/dpdk-l2fwd -l 0-3 -n 4 -- -p 0x3 --no-mac-updating
EAL: Detected 12 lcore(s)
EAL: Detected 1 NUMA nodes
EAL: Detected static linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'VA'
EAL: Probing VFIO support...
EAL: VFIO support initialized
EAL:   using IOMMU type 1 (Type 1)
EAL: Probe PCI driver: net_mqnic (22db:2300) device: 0000:06:00.0 (socket 0)
eth_mqnic_pci_probe():  Vendor: 0x22db
eth_mqnic_pci_probe():  Device: 0x2300
eth_mqnic_pci_probe():  Subsystem vendor: 0x22db
eth_mqnic_pci_probe():  Subsystem device: 0x2301
eth_mqnic_pci_probe():  Class: 0x020000
...
```

### Testpmd

The [testpmd](https://doc.dpdk.org/guides-20.11/testpmd_app_ug/index.html) application allows the developer to test the
drivers functionality. The application can be launched with the following command:

```shell
sudo ./build/app/dpdk-testpmd
```

The output should look similar to the following log:

```
$ sudo ./build/app/dpdk-testpmd
EAL: Detected 8 lcore(s)
EAL: Detected 1 NUMA nodes
EAL: Detected static linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'VA'
EAL: Probing VFIO support...
EAL: VFIO support initialized
EAL:   using IOMMU type 1 (Type 1)
EAL: Probe PCI driver: net_mqnic (1234:1001) device: 0000:06:00.0 (socket 0)
EAL: Error disabling MSI-X interrupts for fd 47
eth_mqnic_pci_probe():  Vendor: 0x22db
eth_mqnic_pci_probe():  Device: 0x2300
eth_mqnic_pci_probe():  Subsystem vendor: 0x22db
eth_mqnic_pci_probe():  Subsystem device: 0x2301
eth_mqnic_pci_probe():  Class: 0x020000
...
```
