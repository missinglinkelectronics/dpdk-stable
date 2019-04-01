..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2018 The DPDK contributors

DPDK Release 18.08
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      make doc-guides-html

      xdg-open build/doc/html/guides/rel_notes/release_18_08.html


New Features
------------

.. This section should contain new features added in this release.
   Sample format:

   * **Add a title in the past tense with a full stop.**

     Add a short 1-2 sentence description in the past tense.
     The description should be enough to allow someone scanning
     the release notes to understand the new feature.

     If the feature adds a lot of sub-features you can use a bullet list
     like this:

     * Added feature foo to do something.
     * Enhanced feature bar to do something else.

     Refer to the previous release notes for examples.

     This section is a comment. Do not overwrite or remove it.
     Also, make sure to start the actual text at the margin.
     =========================================================

* **Added support for Hyper-V netvsc PMD.**

  The new ``netvsc`` poll mode driver provides native support for
  networking on Hyper-V. See the :doc:`../nics/netvsc` NIC driver guide
  for more details on this new driver.

* **Added Flow API support for CXGBE PMD.**

  Flow API support has been added to CXGBE Poll Mode Driver to offload
  flows to Chelsio T5/T6 NICs. Support added for:

  * Wildcard (LE-TCAM) and Exact (HASH) match filters.
  * Match items: physical ingress port, IPv4, IPv6, TCP and UDP.
  * Action items: queue, drop, count, and physical egress port redirect.

* **Added ixgbe preferred Rx/Tx parameters.**

  Rather than applications providing explicit Rx and Tx parameters such as
  queue and burst sizes, they can request that the EAL instead uses preferred
  values provided by the PMD, falling back to defaults within the EAL if the
  PMD does not provide any. The provision of such tuned values now includes
  the ixgbe PMD.

* **Added descriptor status check support for fm10k.**

  The ``rte_eth_rx_descriptor_status`` and ``rte_eth_tx_descriptor_status``
  APIs are now supported by fm10K.

* **Updated the enic driver.**

  * Add low cycle count Tx handler for no-offload Tx.
  * Add low cycle count Rx handler for non-scattered Rx.
  * Minor performance improvements to scattered Rx handler.
  * Add handlers to add/delete VxLAN port number.
  * Add devarg to specify ingress VLAN rewrite mode.

* **Updated mlx5 driver.**

  Updated the mlx5 driver including the following changes:

  * Added port representors support.
  * Added Flow API support for e-switch rules.
    Added support for ACTION_PORT_ID, ACTION_DROP, ACTION_OF_POP_VLAN,
    ACTION_OF_PUSH_VLAN, ACTION_OF_SET_VLAN_VID, ACTION_OF_SET_VLAN_PCP
    and ITEM_PORT_ID.
  * Added support for 32-bit compilation.

* **Added TSO support for the mlx4 driver.**

  Added TSO support for the mlx4 drivers from MLNX_OFED_4.4 and above.

* **SoftNIC PMD rework.**

  The SoftNIC PMD infrastructure has been restructured to use the Packet
  Framework, which makes it more flexible, modular and easier to add new
  functionality in the future.

* **Updated the AESNI MB PMD.**

  The AESNI MB PMD has been updated with additional support for:

  * 3DES for 8, 16 and 24 byte keys.

* **Added a new compression PMD using Intel's QuickAssist (QAT) device family.**

  Added the new ``QAT`` compression driver, for compression and decompression
  operations in software. See the :doc:`../compressdevs/qat_comp` compression
  driver guide for details on this new driver.

* **Updated the ISA-L PMD.**

  Added support for chained mbufs (input and output).


API Changes
-----------

.. This section should contain API changes. Sample format:

   * Add a short 1-2 sentence description of the API change.
     Use fixed width quotes for ``function_names`` or ``struct_names``.
     Use the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =========================================================

* The path to the runtime config file has changed. The new path is determined
  as follows:

  - If DPDK is running as root, ``/var/run/dpdk/<prefix>/config``
  - If DPDK is not running as root:

    * If ``$XDG_RUNTIME_DIR`` is set, ``${XDG_RUNTIME_DIR}/dpdk/<prefix>/config``
    * Otherwise, ``/tmp/dpdk/<prefix>/config``

* eal: The function ``rte_eal_mbuf_default_mempool_ops`` was deprecated
  and is removed in 18.08. It shall be replaced by
  ``rte_mbuf_best_mempool_ops``.

* mempool: Following functions were deprecated and are removed in 18.08:

  - ``rte_mempool_populate_iova_tab``
  - ``rte_mempool_populate_phys_tab``
  - ``rte_mempool_populate_phys`` (``rte_mempool_populate_iova`` should be used)
  - ``rte_mempool_virt2phy`` (``rte_mempool_virt2iova`` should be used)
  - ``rte_mempool_xmem_create``
  - ``rte_mempool_xmem_size``
  - ``rte_mempool_xmem_usage``

* ethdev: The old offload API is removed:

  - Rx per-port ``rte_eth_conf.rxmode.[bit-fields]``
  - Tx per-queue ``rte_eth_txconf.txq_flags``
  - ``ETH_TXQ_FLAGS_NO*``

  The transition bits are removed:

  - ``rte_eth_conf.rxmode.ignore_offload_bitfield``
  - ``ETH_TXQ_FLAGS_IGNORE``

* cryptodev: The following API changes have been made in 18.08:

  - In struct ``struct rte_cryptodev_info``, field ``rte_pci_device *pci_dev``
    has been replaced with field ``struct rte_device *device``.
  - Value 0 is accepted in ``sym.max_nb_sessions``, meaning that a device
    supports an unlimited number of sessions.
  - Two new fields of type ``uint16_t`` have been added:
    ``min_mbuf_headroom_req`` and ``min_mbuf_tailroom_req``.  These parameters
    specify the recommended headroom and tailroom for mbufs to be processed by
    the PMD.

* cryptodev: The following functions were deprecated and are removed in 18.08:

  - ``rte_cryptodev_queue_pair_start``
  - ``rte_cryptodev_queue_pair_stop``
  - ``rte_cryptodev_queue_pair_attach_sym_session``
  - ``rte_cryptodev_queue_pair_detach_sym_session``

* cryptodev: The following functions were deprecated and are replaced by other
  functions in 18.08:

  - ``rte_cryptodev_get_header_session_size`` is replaced with
    ``rte_cryptodev_sym_get_header_session_size``
  - ``rte_cryptodev_get_private_session_size`` is replaced with
    ``rte_cryptodev_sym_get_private_session_size``

* cryptodev: Feature flag ``RTE_CRYPTODEV_FF_MBUF_SCATTER_GATHER`` is
  replaced with the following more explicit flags:

  - ``RTE_CRYPTODEV_FF_IN_PLACE_SGL``
  - ``RTE_CRYPTODEV_FF_OOP_SGL_IN_SGL_OUT``
  - ``RTE_CRYPTODEV_FF_OOP_SGL_IN_LB_OUT``
  - ``RTE_CRYPTODEV_FF_OOP_LB_IN_SGL_OUT``
  - ``RTE_CRYPTODEV_FF_OOP_LB_IN_LB_OUT``

* cryptodev: Renamed cryptodev experimental APIs:

  Used user_data instead of private_data in following APIs to avoid confusion
  with the existing session parameter ``sess_private_data[]`` and related APIs.

  - ``rte_cryptodev_sym_session_set_private_data()`` changed to
    ``rte_cryptodev_sym_session_set_user_data()``
  - ``rte_cryptodev_sym_session_get_private_data()`` changed to
    ``rte_cryptodev_sym_session_get_user_data()``

* compressdev: Feature flag ``RTE_COMP_FF_MBUF_SCATTER_GATHER`` is
  replaced with the following more explicit flags:

  - ``RTE_COMP_FF_OOP_SGL_IN_SGL_OUT``
  - ``RTE_COMP_FF_OOP_SGL_IN_LB_OUT``
  - ``RTE_COMP_FF_OOP_LB_IN_SGL_OUT``


Shared Library Versions
-----------------------

.. Update any library version updated in this release
   and prepend with a ``+`` sign, like this:

     librte_acl.so.2
   + librte_cfgfile.so.2
     librte_cmdline.so.2

   This section is a comment. Do not overwrite or remove it.
   =========================================================

The libraries prepended with a plus sign were incremented in this version.

.. code-block:: diff

     librte_acl.so.2
     librte_bbdev.so.1
     librte_bitratestats.so.2
     librte_bpf.so.1
     librte_bus_dpaa.so.1
     librte_bus_fslmc.so.1
     librte_bus_pci.so.1
     librte_bus_vdev.so.1
   + librte_bus_vmbus.so.1
     librte_cfgfile.so.2
     librte_cmdline.so.2
     librte_common_octeontx.so.1
     librte_compressdev.so.1
   + librte_cryptodev.so.5
     librte_distributor.so.1
   + librte_eal.so.8
   + librte_ethdev.so.10
   + librte_eventdev.so.5
     librte_flow_classify.so.1
     librte_gro.so.1
     librte_gso.so.1
     librte_hash.so.2
     librte_ip_frag.so.1
     librte_jobstats.so.1
     librte_kni.so.2
     librte_kvargs.so.1
     librte_latencystats.so.1
     librte_lpm.so.2
     librte_mbuf.so.4
   + librte_mempool.so.5
     librte_meter.so.2
     librte_metrics.so.1
     librte_net.so.1
     librte_pci.so.1
     librte_pdump.so.2
     librte_pipeline.so.3
     librte_pmd_bnxt.so.2
     librte_pmd_bond.so.2
     librte_pmd_i40e.so.2
     librte_pmd_ixgbe.so.2
     librte_pmd_dpaa2_cmdif.so.1
     librte_pmd_dpaa2_qdma.so.1
     librte_pmd_ring.so.2
     librte_pmd_softnic.so.1
     librte_pmd_vhost.so.2
     librte_port.so.3
     librte_power.so.1
     librte_rawdev.so.1
     librte_reorder.so.1
     librte_ring.so.2
     librte_sched.so.1
     librte_security.so.1
     librte_table.so.3
     librte_timer.so.1
     librte_vhost.so.3


Tested Platforms
----------------

.. This section should contain a list of platforms that were tested
   with this release.

   The format is:

   * <vendor> platform with <vendor> <type of devices> combinations

     * List of CPU
     * List of OS
     * List of devices
     * Other relevant details...

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =========================================================

* Intel(R) platforms with Intel(R) NICs combinations

   * CPU

     * Intel(R) Atom(TM) CPU C3858 @ 2.00GHz
     * Intel(R) Xeon(R) CPU D-1541 @ 2.10GHz
     * Intel(R) Xeon(R) CPU E5-4667 v3 @ 2.00GHz
     * Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
     * Intel(R) Xeon(R) CPU E5-2699 v4 @ 2.20GHz
     * Intel(R) Xeon(R) CPU E5-2695 v4 @ 2.10GHz
     * Intel(R) Xeon(R) CPU E5-2658 v2 @ 2.40GHz
     * Intel(R) Xeon(R) CPU E5-2658 v3 @ 2.20GHz
     * Intel(R) Xeon(R) Platinum 8180 CPU @ 2.50GHz

   * OS:

     * CentOS 7.4
     * Fedora 25
     * Fedora 27
     * Fedora 28
     * FreeBSD 11.1
     * Red Hat Enterprise Linux Server release 7.5
     * SUSE Enterprise Linux 12
     * Wind River Linux 8
     * Ubuntu 14.04
     * Ubuntu 16.04
     * Ubuntu 16.10
     * Ubuntu 17.10
     * Ubuntu 18.04

   * NICs:

     * Intel(R) 82599ES 10 Gigabit Ethernet Controller

       * Firmware version: 0x61bf0001
       * Device id (pf/vf): 8086:10fb / 8086:10ed
       * Driver version: 5.2.3 (ixgbe)

     * Intel(R) Corporation Ethernet Connection X552/X557-AT 10GBASE-T

       * Firmware version: 0x800003e7
       * Device id (pf/vf): 8086:15ad / 8086:15a8
       * Driver version: 4.4.6 (ixgbe)

     * Intel(R) Ethernet Converged Network Adapter X710-DA4 (4x10G)

       * Firmware version: 6.01 0x80003221
       * Device id (pf/vf): 8086:1572 / 8086:154c
       * Driver version: 2.4.6 (i40e)

     * Intel Corporation Ethernet Connection X722 for 10GbE SFP+ (4x10G)

       * Firmware version: 3.33 0x80000fd5 0.0.0
       * Device id (pf/vf): 8086:37d0 / 8086:37cd
       * Driver version: 2.4.3 (i40e)

     * Intel(R) Ethernet Converged Network Adapter XXV710-DA2 (2x25G)

       * Firmware version: 6.01 0x80003221
       * Device id (pf/vf): 8086:158b / 8086:154c
       * Driver version: 2.4.6 (i40e)

     * Intel(R) Ethernet Converged Network Adapter XL710-QDA2 (2X40G)

       * Firmware version: 6.01 0x8000321c
       * Device id (pf/vf): 8086:1583 / 8086:154c
       * Driver version: 2.4.6 (i40e)

     * Intel(R) Corporation I350 Gigabit Network Connection

       * Firmware version: 1.63, 0x80000dda
       * Device id (pf/vf): 8086:1521 / 8086:1520
       * Driver version: 5.4.0-k (igb)

* Intel(R) platforms with Mellanox(R) NICs combinations

   * CPU:

     * Intel(R) Xeon(R) Gold 6154 CPU @ 3.00GHz
     * Intel(R) Xeon(R) CPU E5-2697A v4 @ 2.60GHz
     * Intel(R) Xeon(R) CPU E5-2697 v3 @ 2.60GHz
     * Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
     * Intel(R) Xeon(R) CPU E5-2650 v4 @ 2.20GHz
     * Intel(R) Xeon(R) CPU E5-2640 @ 2.50GHz
     * Intel(R) Xeon(R) CPU E5-2620 v4 @ 2.10GHz

   * OS:

     * Red Hat Enterprise Linux Server release 7.5 (Maipo)
     * Red Hat Enterprise Linux Server release 7.4 (Maipo)
     * Red Hat Enterprise Linux Server release 7.3 (Maipo)
     * Red Hat Enterprise Linux Server release 7.2 (Maipo)
     * Ubuntu 18.04
     * Ubuntu 17.10
     * Ubuntu 16.04
     * SUSE Linux Enterprise Server 15

   * MLNX_OFED: 4.3-2.0.2.0
   * MLNX_OFED: 4.4-2.0.1.0

   * NICs:

     * Mellanox(R) ConnectX(R)-3 Pro 40G MCX354A-FCC_Ax (2x40G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1007
       * Firmware version: 2.42.5000

     * Mellanox(R) ConnectX(R)-4 10G MCX4111A-XCAT (1x10G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 10G MCX4121A-XCAT (2x10G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 25G MCX4111A-ACAT (1x25G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 25G MCX4121A-ACAT (2x25G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 40G MCX4131A-BCAT/MCX413A-BCAT (1x40G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 40G MCX415A-BCAT (1x40G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 50G MCX4131A-GCAT/MCX413A-GCAT (1x50G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 50G MCX414A-BCAT (2x50G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 50G MCX415A-GCAT/MCX416A-BCAT/MCX416A-GCAT (2x50G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 50G MCX415A-CCAT (1x100G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 100G MCX416A-CCAT (2x100G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1013
       * Firmware version: 12.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 Lx 10G MCX4121A-XCAT (2x10G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1015
       * Firmware version: 14.21.1000 and above

     * Mellanox(R) ConnectX(R)-4 Lx 25G MCX4121A-ACAT (2x25G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1015
       * Firmware version: 14.21.1000 and above

     * Mellanox(R) ConnectX(R)-5 100G MCX556A-ECAT (2x100G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1017
       * Firmware version: 16.21.1000 and above

     * Mellanox(R) ConnectX-5 Ex EN 100G MCX516A-CDAT (2x100G)

       * Host interface: PCI Express 4.0 x16
       * Device ID: 15b3:1019
       * Firmware version: 16.21.1000 and above

* ARM platforms with Mellanox(R) NICs combinations

   * CPU:

     * Qualcomm ARM 1.1 2500MHz

   * OS:

     * Red Hat Enterprise Linux Server release 7.5 (Maipo)

   * NICs:

     * Mellanox(R) ConnectX(R)-4 Lx 25G MCX4121A-ACAT (2x25G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1015
       * Firmware version: 14.23.1000

     * Mellanox(R) ConnectX(R)-5 100G MCX556A-ECAT (2x100G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1017
       * Firmware version: 16.23.1000

* Mellanox BlueField SmartNIC

   * Mellanox(R) BlueField SmartNIC MT416842 (2x25G)
       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:a2d2
       * Firmware version: 18.99.3950

   * SoC ARM cores running OS:
     * CentOS Linux release 7.4.1708 (AltArch)
     * Mellanox MLNX_OFED 4.2-1.4.21.0

  * DPDK application running on ARM cores inside SmartNIC
  * Bluefield representors support planned for next release.

18.08.1
~~~~~~~

No regressions from 18.08 with basic Intel NIC(ixgbe and i40e),
cryptodev, virtio and Intel NIC/virtio performance tests.

No regressions from 18.08 with virtualization testing on PF/VF,
PVP, PVP multiqueue, vhost-user reconnect and live migration.
Tested on X540-AT2(ixgbe).

Fixes in 18.08 Stable Release
-----------------------------

18.08.1
~~~~~~~

* acl: forbid rule with priority zero
* app/bbdev: fix inputs mbuf creation
* app/eventdev: fix minor typos
* app/pdump: fix port id storage size
* app/test-crypto-perf: fix check for auth key
* app/test-crypto-perf: fix check for cipher IV
* app/test-crypto-perf: fix double allocation of memory
* app/testpmd: check Rx VLAN offload flag to print VLAN TCI
* app/testpmd: fix csum parse-tunnel command invocation
* app/testpmd: fix displaying RSS hash functions
* app/testpmd: fix duplicate exit
* app/testpmd: fix L4 length for UDP checksum
* app/testpmd: fix memory allocation for DSCP table
* app/testpmd: fix memory leak for DSCP table
* app/testpmd: fix memory leak for TM object
* app/testpmd: fix metering and policing commands
* app/testpmd: fix missing jump action in flow action
* app/testpmd: fix physical port socket initialization
* app/testpmd: fix port status for new bonded devices
* app/testpmd: fix printf format in event callback
* app/testpmd: fix QinQ strip display option
* app/testpmd: fix RED byte stats
* app/testpmd: fix Rx offload search
* app/testpmd: fix shaper profile parameters
* app/testpmd: fix Tx offload flags
* app/testpmd: fix vdev socket initialization
* app/testpmd: optimize mbuf pool allocation
* app/testpmd: reserve NUMA node per port and per ring
* bpf: fix a typo
* bpf: fix x86 JIT for immediate loads
* build: create relative symlinks for PMDs in libdir
* build: enable ARM NEON flag when __aarch64__ defined
* build: set -mfpu=neon flag for armv7-a with meson
* bus/dpaa: fix build with gcc 9.0
* bus/fslmc: fix physical addressing check
* bus/pci: compare kernel driver instead of interrupt handler
* bus/pci: fix allocation of device path
* bus/pci: fix config r/w access
* bus/vdev: fix devargs after multi-process bus scan
* bus/vdev: fix error log on secondary device scan
* bus/vdev: fix multi-process IPC buffer leak on scan
* bus/vmbus: fix directory handle leak on error
* common/qat: fix failure to create PMD
* common/qat: fix for invalid response from firmware
* common/qat: remove check of valid firmware response
* compat: fix symbol version support with meson
* compressdev: clarify usage of op structure
* compressdev: fix compression API description
* compressdev: fix op allocation
* compress/isal: fix uncleared compression states
* compress/qat: fix checksum on decompression
* compress/qat: remove unnecessary assignment
* config: enable more than 128 cores for arm64
* config: remove unused parameter
* crypto/aesni_mb: fix possible array overrun
* crypto/aesni_mb: fix queue pair free
* crypto/aesni_mb: fix truncated digest size for CMAC
* crypto/ccp: fix resource leak
* cryptodev: fix library version
* cryptodev: fix pool element size for undefined operation
* crypto/mvsam: fix shared library build
* crypto/mvsam: update hash digest sizes
* crypto/openssl: fix RSA verify operation
* crypto/qat: fix typo
* crypto/scheduler: fix build with gcc 8.2
* devargs: fix variadic parsing memory leak
* devtools: fix regex in symbol addition check
* devtools: fix symbol check when adding experimental section
* devtools: relax rule for identifying symbol section
* doc: add cross-compilation in sample apps guide
* doc: add VFIO in ENA guide
* doc: clarify L3 Tx checksum prerequisite
* doc: clarify L4 Tx checksum prerequisite
* doc: clarify TSO Tx offload prerequisite
* doc: clarify VLAN and QinQ Tx offload prerequisite
* doc: fix a typo in testpmd guide
* doc: fix DESTDIR variable name in meson guide
* doc: fix eventdev shared library version
* doc: fix formatting in IP reassembly app guide
* doc: fix function name in flow filtering app guide
* doc: fix missing CCM to QAT feature list
* doc: fix NUMA library name in Linux guide
* doc: fix spelling in PMD guides
* doc: fix style and syntax in flow API guide
* doc: fix typo for cryptodev
* doc: fix typo in testpmd guide
* doc: fix typos in the flow API guide
* doc: fix wrong usage of bind command
* doc: remove invalid config option from ena guide
* doc: remove invalid config options from liquidio guide
* doc: remove old options from pdump guide
* drivers/crypto: fix wrongly assignment of digest_len
* drivers/net: fix log type string
* drivers/net: fix several Tx prepare functions
* eal/bsd: fix possible IOPL fd leak
* eal: do not allow legacy mode with --in-memory mode
* eal: fix build with gcc 9.0
* eal: fix build with -O1
* eal: include missing hypervisor files in meson
* eal/linux: fix memory leak of logid
* eal/linux: handle UIO read failure in interrupt handler
* eal: use correct data type for bitmap slab operations
* eal/x86: remove unused memcpy file
* efd: fix write unlock during ring creation
* ethdev: eliminate interim variable
* ethdev: fix device info getting
* ethdev: fix doxygen comments of shared data fields
* ethdev: fix doxygen comment to be with structure
* ethdev: fix error handling in create function
* ethdev: fix invalid configuration after failure
* ethdev: fix MAC changes when live change not supported
* ethdev: fix missing names in Tx offload name array
* ethdev: fix port ownership logs
* ethdev: fix redundant function pointer check
* ethdev: fix typo in queue setup error log
* eventdev: fix eth Rx adapter hotplug incompatibility
* eventdev: fix unlock in Rx adapter
* event/dpaa2: fix mbuf assignment in atomic processing
* event/sw: fix cq index check for unlink usecases
* examples/bond: fix crash when there is no active slave
* examples/flow_filtering: filter out unsupported offloads
* examples/flow_filtering: fix capability setting
* examples/flow_filtering: remove VLAN item
* examples/ip_pipeline: fix IPv6 endianness
* examples/ip_pipeline: fix port and table stats read
* examples/ipsec-secgw: fix wrong session size
* examples/ipv4_multicast: fix leak of cloned packets
* examples/l3fwd-power: fix power library fallback
* examples/vhost: remove unnecessary constant
* examples/vm_power: respect maximum CPUs
* fbarray: fix detach in --no-shconf mode
* fix dpdk.org URLs
* fix global variable issues
* fix indentation in symbol maps
* hash: fix key store element alignment
* hash: fix race condition in iterate
* hash: fix TSX aborts with newer gcc
* hash: remove unnecessary pause
* hash: remove unused constant
* igb_uio: fix refcount if open returns error
* igb_uio: fix unexpected removal for hot-unplug
* igb_uio: install module when building with meson
* ipc: fix access after async request failure
* ipc: fix undefined behavior in no-shconf mode
* ipc: remove panic in async request
* ip_frag: check fragment length of incoming packet
* ip_frag: fix overflow in key comparison
* kni: fix build on Linux < 3.14
* kni: fix build on Linux 4.19
* kni: fix FIFO synchronization
* kni: fix kernel FIFO synchronization
* kni: fix possible uninitialized variable
* kvargs: fix processing a null list
* latency: fix timestamp marking and latency calculation
* lib: fix shifting 32-bit signed variable 31 times
* malloc: check size hint when reserving the biggest element
* malloc: fix adjacency check to also include segment list
* malloc: fix potential null pointer dereference
* malloc: notify primary process about hotplug in secondary
* mbuf: fix library version on meson build
* mbuf: fix offload flag name and list
* mbuf: fix Tx offload mask
* mem: fix division by zero in no-NUMA mode
* mem: fix --huge-unlink option
* mem: fix resource leak
* mem: fix undefined behavior in NUMA-aware mapping
* mem: improve segment list preallocation
* mk: disable gcc AVX512F support
* mk: disable OcteonTx for buggy compilers only on arm64
* net/avf/base: fix shifting 32-bit signed variable 31 times
* net/avf: fix build with debug enabled
* net/avf: fix missing compiler error flags
* net/avf: fix Tx offload mask
* net/avf: fix unused variables and label
* net/avf: remove keeping CRC configuration
* net/avp: disable in FreeBSD build with meson
* net/bnx2x: cleanup info logs
* net/bnx2x: fix call to link handling periodic function
* net/bnx2x: fix dynamic logging
* net/bnx2x: fix info logs backport
* net/bnx2x: fix logging to include device name
* net/bnx2x: fix to add PHY lock
* net/bnx2x: fix to disable further interrupts
* net/bnx2x: fix VF link state update
* net/bnxt: fix MTU setting
* net/bnxt: fix registration of VF async event completion ring
* net/bnxt: fix uninitialized pointer access in Tx
* net/bnxt: fix uninitialized variable access
* net/bnxt: get rid of ff pools and use VNIC info array
* net/bnxt: reduce polling interval for valid bit
* net/bnxt: remove excess log messages
* net/bnxt: set a VNIC as default only once
* net/bnxt: set MAC filtering as outer for non tunnel frames
* net/bnxt: set VLAN strip mode before default VNIC cfg
* net/bonding: do not ignore RSS key on device config
* net/bonding: fix buffer corruption in packets
* net/bonding: fix crash on probe
* net/bonding: fix crash when stopping mode 4 port
* net/bonding: fix possible silent failure in configuration
* net/bonding: fix Rx slave fairness
* net/bonding: stop and deactivate slaves on stop
* net/bonding: support matching QinQ ethertype
* net/bonding: use evenly distributed default RSS RETA
* net/cxgbe: announce Rx scatter offload
* net/cxgbe: check Rx config before doing VLAN strip offload
* net/cxgbe: fix check for redefined match items
* net/cxgbe: fix control queue mbuf pool naming convention
* net/cxgbe: fix memory access when parsing flow match items
* net/cxgbe: fix wrong ingress port value set in filter spec
* net/cxgbe: increase completion wait time for flow operations
* net/cxgbevf: add PCI uninitialization for VF
* net/dpaa2: fix IOVA conversion for congestion memory
* net/dpaa2: fix VLAN filter enablement
* net/dpaa: fix jumbo buffer config
* net/dpaa: fix link speed based on MAC type
* net/e1000/base: fix uninitialized variable
* net/e1000: do not error out if Rx drop enable is set
* net/e1000: fix missing Tx multi-segs capability
* net/e1000: fix queue number in RSS configuration
* net/e1000: fix Tx offload capability typos
* net/ena: fix cleaning HW IO rings configuration
* net/ena: fix out of order completion
* net/ena: fix passing RSS hash to mbuf
* net/ena: recreate HW IO rings on start and stop
* net/enic: do not use non-standard integer types
* net/enic: explicitly disable overlay offload
* net/enic: fix flow API memory leak
* net/enic: fix size check in Tx prepare handler
* net/enic: fix supported packet types
* net/enic: set Rx VLAN offload flag for non-stripped packets
* net/failsafe: add checks for deferred queue setup
* net/failsafe: fix crash on slave queue release
* net/failsafe: remove not supported multicast MAC filter
* net/failsafe: report actual device capabilities
* net/failsafe: use prefix for function
* net: fix build with pedantic
* net: fix Intel prepare function for IP checksum offload
* net/fm10k: fix missing Tx multi-segs capability
* net/i40e/base: correct global reset timeout calculation
* net/i40e/base: fix comment referencing internal data
* net/i40e/base: fix partition id calculation for X722
* net/i40e/base: gracefully clean the resources
* net/i40e/base: improve the polling mechanism
* net/i40e/base: properly clean resources
* net/i40e/base: read LLDP config area with correct endianness
* net/i40e: cancel alarm handler at the end of closure
* net/i40e: enable loopback function for X722 MAC
* net/i40e: fix 25G AOC and ACC cable detection on XXV710
* net/i40e: fix getting RSS configuration
* net/i40e: fix missing Tx multi-segs capability
* net/i40e: fix offload not supported mask
* net/i40e: fix overwriting RSS RETA
* net/i40e: fix port close
* net/i40e: fix Rx instability with vector mode
* net/i40e: fix send admin queue command before init
* net/i40e: fix X710 Rx after reading some registers
* net/i40e: keep promiscuous on if allmulticast is enabled
* net/i40e: remove redundant reset of queue number
* net/i40e: revert fix offload not supported mask
* net/i40e: update Tx offload mask
* net/i40e: use -Wno-error=format-security for meson
* net/ifc: do not notify before HW ready
* net/ifc: fix address translation function name
* net/ifcvf: fix typo on struct name
* net/igb: update Tx offload mask
* net/ixgbe/base: add LHA ID
* net/ixgbe: do not return internal code
* net/ixgbe: fix busy polling while fiber link update
* net/ixgbe: fix flow create in ntuple check
* net/ixgbe: fix maximum wait time in comment
* net/ixgbe: fix missing Tx multi-segs capability
* net/ixgbe: fix overwriting RSS RETA
* net/ixgbe: fix RSS flow error return
* net/ixgbe: fix Rx LRO capability offload for x550
* net/ixgbe: fix TDH register write
* net/ixgbe: stop link setup alarm handler before start
* net/ixgbe: update Tx offload mask
* net/ixgbevf: fix link state
* net/ixgbe: wait longer for link after fiber MAC setup
* net/mlx4: fix initialization of struct members
* net/mlx4: fix minor typo
* net/mlx4: fix possible uninitialized variable
* net/mlx4: optimize Tx external memory registration
* net/mlx4: support externally allocated static memory
* net/mlx5: add representor specific statistics
* net/mlx5: always use representor ifindex for ioctl
* net/mlx5: disable ConnectX-4 Lx Multi Packet Send by default
* net/mlx5: fallback quietly if pkg-config is unavailable
* net/mlx5: fix artificial L4 limitation on switch flow rules
* net/mlx5: fix errno values for flow engine
* net/mlx5: fix function documentation
* net/mlx5: fix initialization of struct members
* net/mlx5: fix interrupt completion queue index wrapping
* net/mlx5: fix minor typos
* net/mlx5: fix packet type for MPLS in UDP
* net/mlx5: fix representor port link status
* net/mlx5: fix representor port xstats
* net/mlx5: fix RSS flow action hash type selection
* net/mlx5: fix validation of Rx queue number
* net/mlx5: optimize Rx buffer replenishment threshold
* net/mlx5: optimize Tx doorbell write
* net/mlx5: optimize Tx external memory registration
* net/mlx5: support externally allocated static memory
* net/mlx5: support missing counter in extended statistics
* net/mlx5: use pkg-config to handle SUSE libmnl
* net/mvpp2: fix array initialization
* net/mvpp2: fix comments and error messages
* net/netvsc: fix chimney buffer size error handling
* net/netvsc: resize event buffer as needed
* net/nfp: disable in FreeBSD build with meson
* net/nfp: fix live MAC changes not supported
* net/nfp: fix mbuf flags with checksum good
* net/nfp: fix RSS
* net/octeontx: fix failures when available ports > queues
* net/octeontx: fix mbuf corruption with large private sizes
* net/octeontx: fix packet corruption on Tx
* net/qede/base: fix logic for sfp get/set
* net/qede/base: fix MFW FLR flow
* net/qede/base: fix to handle stag update event
* net/qede: fix crash when configure fails
* net/qede: fix ethernet type in HW registers
* net/qede: fix flow director for IPv6 filter
* net/qede: fix Rx buffer size calculation
* net/qede: fix Tx offload mask
* net/qede: fix Tx tunnel offload support mask
* net/qede: remove invalid config option checks
* net/sfc: allow to query RSS key and HF in isolated mode
* net/sfc: allow to query RSS key and HF when RSS is disabled
* net/sfc/base: add check for TUNNEL module in NIC reset API
* net/sfc/base: add space after sizeof
* net/sfc/base: avoid usage of too big arrays on stack
* net/sfc/base: check size of memory to read sensors data to
* net/sfc/base: fix a typo in unicast filter insertion comment
* net/sfc/base: fix build because of no declaration
* net/sfc/base: fix field order in filter spec struct
* net/sfc/base: fix ID retrieval in v3 licensing
* net/sfc/base: fix invalid order of memset arguments
* net/sfc/base: fix MAC Tx stats for less or equal to 64 bytes
* net/sfc/base: fix name of the argument to store RSS flags
* net/sfc/base: fix outer IPID field in TSO option descriptors
* net/sfc/base: fix out of bounds read when dereferencing sdup
* net/sfc/base: fix output buffer SAL annotation
* net/sfc/base: fix PreFAST warnings because of unused return
* net/sfc/base: fix SAL annotation for input buffers
* net/sfc/base: make last byte of module information available
* net/sfc/base: prevent access to the NIC config before probe
* net/sfc/base: properly align on line continuation
* net/sfc: do not skip RSS configuration step on reconfigure
* net/sfc: fix an Rx queue double release possibility
* net/sfc: fix a Tx queue double release possibility
* net/sfc: receive prepared packets even in Rx exception case
* net/softnic: disable in FreeBSD build with meson
* net/softnic: fix IPv6 endianness
* net/tap: fix file descriptor check
* net/tap: fix file descriptor leak on error
* net/tap: fix probe for multiq or flowq failure
* net/tap: fix reported number of Tx packets
* net/thunderx: fix Tx desc corruption in scatter-gather mode
* net/vhost: fix parameters string
* net/virtio: add missing supported features
* net/virtio: avoid annoying IOPL error log
* net/virtio: do not re-enter clean up routines
* net/virtio: fix guest announce support
* net/virtio: fix unchecked return value
* net/virtio: register/unregister intr handler on start/stop
* net/virtio-user: check negotiated features before set
* net/virtio-user: do not make vhost channel non-block
* net/virtio-user: do not reset owner when driver resets
* net/virtio-user: do not stop stopped device again
* net/virtio-user: fix deadlock in memory events callback
* net/virtio-user: fix device features for server mode
* net/virtio-user: fix memory hotplug support in vhost-kernel
* net/virtio-user: fix multiple queue for vhost-kernel
* net/virtio-user: fix typo in error message
* net/vmxnet3: fix hot-unplug
* pci: fix parsing of address without function number
* pdump: remove dependency on libpthread
* raw/ifpga: check probing error
* raw/ifpga: use -Wno-error=format-security for meson
* raw/skeleton: fix memory leak on test failure
* Revert "raw/skeleton: fix memory leak on test failure"
* ring: add library version to meson build
* ring/c11: keep deterministic order allowing retry to work
* ring/c11: move atomic load of head above the loop
* ring/c11: relax ordering for load and store of the head
* ring/c11: synchronize load and store of the tail
* service: fix possible null access
* test/crypto: fix number of queue pairs
* test/event: check burst mode capability
* test/event: fix build for timer adapter
* test/event: fix eth Rx adapter test for skeleton PMD
* test/event: fix RSS config for eth Rx adapter
* test/event: fix Rx adapter intr test for skeleton PMD
* test/event: remove eth Rx adapter vdev workaround
* test: fix build
* test: fix interrupt check
* test/hash: add missing file in meson build
* test/hash: fix bucket size in perf test
* test/hash: fix build
* test/hash: fix r/w test with non-consecutive cores
* test/kni: check module dependency
* test/kni: fix module miss fallback
* test/power: fix ACPI cpufreq module miss fallback
* test/power: skip KVM autotest if cannot run
* test: release ring resources after PMD perf test
* test/reorder: fix out of bound access
* usertools: check for lspci dependency
* version: 18.08.1-rc1
* version: 18.08.1-rc2
* version: 18.08.1-rc3
* vfio: check if group fd is already open
* vfio: disable in FreeBSD build with meson
* vfio: do not needlessly setup device in secondary process
* vfio: fix read of freed memory on getting container fd
* vfio: fix sPAPR IOMMU mapping
* vfio: share default container in multi-process
* vhost: avoid memory barriers when no descriptors dequeued
* vhost/crypto: fix inferred misuse of enum
* vhost/crypto: fix packet copy in chaining mode
* vhost/crypto: fix shared lib build without cryptodev
* vhost: fix corner case for enqueue operation
* vhost: fix crash after mmap failure
* vhost: fix double read of descriptor flags
* vhost: fix error handling when mem table gets updated
* vhost: fix IOVA access for packed ring
* vhost: fix notification for packed ring
* vhost: fix packed ring constants declaration
* vhost: fix payload size of reply
* vhost: fix possible out of bound access
* vhost: fix return value on enqueue path
* vhost: fix vector filling for packed ring
* vhost: fix vhost interrupt support
* vhost: fix zmbufs array leak after NUMA realloc
* vhost: remove unneeded null pointer check
* vhost-user: drop connection on message handling failures
