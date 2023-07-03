/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) 2021-2023 Missing Link Electronics, Inc.
 */

#include "rte_eth_mqnic.h"

static int mqnic_dev_configure(struct rte_eth_dev *dev);
static int eth_mqnic_pci_remove(struct rte_pci_device *pci_dev);
static int eth_mqnic_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev);
static int mqnic_dev_info_get(struct rte_eth_dev *dev,
	struct rte_eth_dev_info *dev_info);
static int eth_mqnic_dev_init(struct rte_eth_dev *eth_dev,
	void *init_params __rte_unused);
static int __rte_cold mqnic_dev_rx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx,
	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_rxconf *rx_conf,
	struct rte_mempool *mp);
int __rte_cold mqnic_dev_rx_queue_start(struct rte_eth_dev *dev,
	uint16_t rx_queue_id);
int __rte_cold mqnic_dev_rx_queue_stop(struct rte_eth_dev *dev,
	uint16_t rx_queue_id);
void mqnic_dev_rx_queue_release(struct rte_eth_dev *dev, uint16_t qid);
static int __rte_cold mqnic_dev_tx_queue_setup(struct rte_eth_dev *dev,
	uint16_t queue_idx,
	uint16_t nb_desc,
	unsigned int socket_id,
	const struct rte_eth_txconf *tx_conf);
int __rte_cold mqnic_dev_tx_queue_start(struct rte_eth_dev *dev,
	uint16_t tx_queue_id);
int __rte_cold mqnic_dev_tx_queue_stop(struct rte_eth_dev *dev,
	uint16_t tx_queue_id);
void mqnic_dev_tx_queue_release(struct rte_eth_dev *dev, uint16_t qid);
static int mqnic_dev_start(struct rte_eth_dev *dev);
static int mqnic_dev_stop(struct rte_eth_dev *dev);
static int mqnic_dev_link_update(__rte_unused struct rte_eth_dev *dev,
	__rte_unused int wait_to_complete);
static int mqnic_promiscuous_enable(__rte_unused struct rte_eth_dev *dev);
static int mqnic_dev_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats);
static void mqnic_common_remove(struct mqnic_dev *mqnic);

void generate_random_mac(struct rte_ether_addr *addr); 

unsigned int mqnic_num_tx_queue_entries = 1024;
unsigned int mqnic_num_rx_queue_entries = 1024;

static uint16_t
mqnic_packet_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct mqnic_ring *pkt_q = queue;
	int packets_read = mqnic_process_rx_cq(pkt_q, nb_pkts, bufs);
	return packets_read;
}

static uint16_t
mqnic_packet_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct mqnic_ring *pkt_q = queue;
	uint16_t packets_send = 0;
	uint16_t desc_freed = 0;
	for(uint16_t i = 0; i < nb_pkts; ++i) {
		if(!mqnic_start_xmit(pkt_q, *bufs++))
			break;
		packets_send++;
	}

	while(desc_freed != packets_send)
		desc_freed += mqnic_process_tx_cq(pkt_q);

	return packets_send;
}

/*
 * Reset and stop device.
 */
static int
mqnic_dev_close(struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();
	PMD_INIT_LOG(NOTICE, "");
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	struct mqnic_if *interface = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);

	for (uint64_t i = 0; i < dev->data->nb_rx_queues; ++i) {
		if (priv->rx_ring[i])
			mqnic_dev_rx_queue_release(dev, i);
	}
	for (uint64_t i = 0; i < dev->data->nb_tx_queues; ++i) {
		if (priv->tx_ring[i])
			mqnic_dev_tx_queue_release(dev, i);
	}
	for (uint8_t k = 0; k < interface->port_count; k++) {
		if (interface->port[k])
			mqnic_destroy_port(&interface->port[k]);
	}
	return 0;
}

static int
mqnic_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct mqnic_if *interface = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
	uint32_t new_mtu = mtu + ETH_LEN;
	PMD_INIT_FUNC_TRACE();
	if(new_mtu > interface->max_rx_mtu || new_mtu > interface->max_tx_mtu){
		PMD_INIT_LOG(ERR, "Bad MTU");
		return -1;
	}

	PMD_INIT_LOG(NOTICE, "MTU from App: %d", mtu);
	interface->tx_mtu = mtu;
	interface->rx_mtu = mtu;
	return 0;
}


/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id pci_id_mqnic_map[] = {
	{RTE_PCI_DEVICE(0x1234, 0x1001)},
	{RTE_PCI_DEVICE(0x5543, 0x1001)},
	{.vendor_id = 0},
};

static const struct eth_dev_ops mqnic_eth_dev_ops = {
	.dev_configure		= mqnic_dev_configure,
	.dev_infos_get		= mqnic_dev_info_get,
	.rx_queue_start		= mqnic_dev_rx_queue_start,
	.rx_queue_stop		= mqnic_dev_rx_queue_stop,
	.tx_queue_start		= mqnic_dev_tx_queue_start,
	.tx_queue_stop		= mqnic_dev_tx_queue_stop,
	.rx_queue_setup		= mqnic_dev_rx_queue_setup,
	.rx_queue_release	= mqnic_dev_rx_queue_release,
	.tx_queue_setup		= mqnic_dev_tx_queue_setup,
	.tx_queue_release	= mqnic_dev_tx_queue_release,
	.dev_start		= mqnic_dev_start,
	.dev_stop		= mqnic_dev_stop,
	.link_update		= mqnic_dev_link_update,
	.promiscuous_enable 	= mqnic_promiscuous_enable,
	.dev_close		= mqnic_dev_close,
	.mtu_set		= mqnic_dev_mtu_set,
	.stats_get		= mqnic_dev_stats_get,
};

static struct rte_pci_driver rte_mqnic_pmd = {
	.id_table  = pci_id_mqnic_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe	   = eth_mqnic_pci_probe,
	.remove	   = eth_mqnic_pci_remove,
};

static int
mqnic_common_probe(struct mqnic_dev *mqnic)
{
	int ret = 0;
	struct mqnic_reg_block *rb;

	mqnic->rb_list = mqnic_enumerate_reg_block_list(mqnic->hw_addr, 0, mqnic->hw_regs_size);
	if (!mqnic->rb_list) {
		PMD_INIT_LOG(ERR, "Failed to enumerate blocks");
		return -EIO;
	}

	for (rb = mqnic->rb_list; rb->regs; rb++)
		PMD_INIT_LOG(NOTICE, " type 0x%08x (v %d.%d.%d.%d)", rb->type, rb->version >> 24,
					(rb->version >> 16) & 0xff,
					(rb->version >> 8) & 0xff, rb->version & 0xff);

	// Read ID registers
	PMD_INIT_LOG(NOTICE, "Find Register Block");
	mqnic->fw_id_rb = mqnic_find_reg_block(mqnic->rb_list, MQNIC_RB_FW_ID_TYPE, MQNIC_RB_FW_ID_VER, 0);


	if (!mqnic->fw_id_rb) {
		ret = -EIO;
		PMD_INIT_LOG(ERR, "Error: FW ID block not found");
		goto fail_rb_init;
	}

	mqnic->fpga_id = rte_read32(mqnic->fw_id_rb->regs + MQNIC_RB_FW_ID_REG_FPGA_ID);
	mqnic->fw_id = rte_read32(mqnic->fw_id_rb->regs + MQNIC_RB_FW_ID_REG_FW_ID);
	mqnic->fw_ver = rte_read32(mqnic->fw_id_rb->regs + MQNIC_RB_FW_ID_REG_FW_VER);
	mqnic->board_id = rte_read32(mqnic->fw_id_rb->regs + MQNIC_RB_FW_ID_REG_BOARD_ID);
	mqnic->board_ver = rte_read32(mqnic->fw_id_rb->regs + MQNIC_RB_FW_ID_REG_BOARD_VER);
	mqnic->build_date = rte_read32(mqnic->fw_id_rb->regs + MQNIC_RB_FW_ID_REG_BUILD_DATE);
	mqnic->git_hash = rte_read32(mqnic->fw_id_rb->regs + MQNIC_RB_FW_ID_REG_GIT_HASH);
	mqnic->rel_info = rte_read32(mqnic->fw_id_rb->regs + MQNIC_RB_FW_ID_REG_REL_INFO);

	PMD_INIT_LOG(NOTICE, "FPGA ID: 0x%08x", mqnic->fpga_id);
	PMD_INIT_LOG(NOTICE, "FW ID: 0x%08x", mqnic->fw_id);
	PMD_INIT_LOG(NOTICE, "FW version: %d.%d.%d.%d", mqnic->fw_ver >> 24, (mqnic->fw_ver >> 16) & 0xff,
				 (mqnic->fw_ver >> 8) & 0xff, mqnic->fw_ver & 0xff);
	PMD_INIT_LOG(NOTICE, "Board ID: 0x%08x", mqnic->board_id);
	PMD_INIT_LOG(NOTICE, "Board version: %d.%d.%d.%d", mqnic->board_ver >> 24,
				(mqnic->board_ver >> 16) & 0xff,
				(mqnic->board_ver >> 8) & 0xff, mqnic->board_ver & 0xff);
	PMD_INIT_LOG(NOTICE, "Git hash: %08x", mqnic->git_hash);
	PMD_INIT_LOG(NOTICE, "Release info: %08x", mqnic->rel_info);

	rb = mqnic_find_reg_block(mqnic->rb_list, MQNIC_RB_APP_INFO_TYPE, MQNIC_RB_APP_INFO_VER, 0);

	if (rb) {
		mqnic->app_id = rte_read32(rb->regs + MQNIC_RB_APP_INFO_REG_ID);
		PMD_INIT_LOG(ERR, "Application ID: 0x%08x", mqnic->app_id);
	}

	mqnic->phc_rb = mqnic_find_reg_block(mqnic->rb_list, MQNIC_RB_PHC_TYPE, MQNIC_RB_PHC_VER, 0);

	// Enumerate interfaces
	mqnic->if_rb = mqnic_find_reg_block(mqnic->rb_list, MQNIC_RB_IF_TYPE, MQNIC_RB_IF_VER, 0);

	if (!mqnic->if_rb) {
		ret = -EIO;
		PMD_INIT_LOG(ERR, "Error: interface block not found");
		goto fail_rb_init;
	}

	mqnic->if_offset = rte_read32(mqnic->if_rb->regs + MQNIC_RB_IF_REG_OFFSET);
	mqnic->if_count = rte_read32(mqnic->if_rb->regs + MQNIC_RB_IF_REG_COUNT);
	mqnic->if_stride = rte_read32(mqnic->if_rb->regs + MQNIC_RB_IF_REG_STRIDE);
	mqnic->if_csr_offset = rte_read32(mqnic->if_rb->regs + MQNIC_RB_IF_REG_CSR_OFFSET);

	PMD_INIT_LOG(NOTICE, "IF offset: 0x%08x", mqnic->if_offset);
	PMD_INIT_LOG(NOTICE, "IF count: %d", mqnic->if_count);
	PMD_INIT_LOG(NOTICE, "IF stride: 0x%08x", mqnic->if_stride);
	PMD_INIT_LOG(NOTICE, "IF CSR offset: 0x%08x", mqnic->if_csr_offset);

	// check BAR size
	if (mqnic->if_count * mqnic->if_stride > mqnic->hw_regs_size) {
		ret = -EIO;
		PMD_INIT_LOG(ERR, "Invalid BAR configuration (%d IF * 0x%x > 0x%lx)", mqnic->if_count,
					mqnic->if_stride,
					mqnic->hw_regs_size);
		goto fail_bar_size;
	}

	// Set up interfaces
	mqnic->dev_port_max = 0;
	mqnic->dev_port_limit = MQNIC_MAX_IF;

	mqnic->if_count = RTE_MIN(mqnic->if_count, (uint32_t)MQNIC_MAX_IF);
	mqnic->initialised = 0;

	ret = mqnic_create_interface(mqnic, &mqnic->interface[0], 0, mqnic->hw_addr + 0 * mqnic->if_stride);

	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to create interface: %d", ret);
		return ret;
	}
	mqnic->dev_port_max = mqnic->interface[0]->dev_port_max;

	return ret;

fail_bar_size:
fail_rb_init:
	mqnic_common_remove(mqnic);
	return ret;
}

static inline int
mqnic_dev_pci_specific_init(struct rte_eth_dev *eth_dev, void *bus_device)
{

	struct mqnic_dev *mqnic;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(eth_dev->data->dev_private);
	int ret;

	PMD_INIT_FUNC_TRACE();

	mqnic = rte_zmalloc(NULL, sizeof(struct mqnic_dev), RTE_CACHE_LINE_SIZE);
	if (!mqnic)
		return -ENOMEM;

	priv->dev = eth_dev;
	priv->mdev = mqnic;

	mqnic->hw_addr = (void *)pci_dev->mem_resource[0].addr;

	mqnic->hw_regs_size = (uint64_t)pci_dev->mem_resource[0].len;
	mqnic->hw_regs_phys = (uint64_t)pci_dev->mem_resource[0].phys_addr;
	mqnic->app_hw_regs_size = (uint64_t)pci_dev->mem_resource[2].len;
	mqnic->app_hw_regs_phys = (uint64_t)pci_dev->mem_resource[2].phys_addr;
	mqnic->ram_hw_regs_size = (uint64_t)pci_dev->mem_resource[4].len;
	mqnic->ram_hw_regs_phys = (uint64_t)pci_dev->mem_resource[4].phys_addr;

	mqnic->hw_addr = mqnic->hw_addr;

	PMD_INIT_LOG(NOTICE, "Control BAR size: %lu", mqnic->hw_regs_size);
	if (!mqnic->hw_addr) {
		ret = -ENOMEM;
		PMD_INIT_LOG(ERR, "Failed to map control BAR");
	}

	if (mqnic->app_hw_regs_phys) {
		PMD_INIT_LOG(NOTICE, "Application BAR size: %lu", mqnic->app_hw_regs_size);
		mqnic->app_hw_addr = (void *)pci_dev->mem_resource[2].addr;
		if (!mqnic->app_hw_addr) {
			ret = -ENOMEM;
			PMD_INIT_LOG(ERR, "Failed to map application BAR");
		}
	}

	if (mqnic->ram_hw_regs_phys) {
		PMD_INIT_LOG(NOTICE, "RAM BAR size: %lu", mqnic->ram_hw_regs_size);
		mqnic->ram_hw_addr = (void *)pci_dev->mem_resource[4].addr;
		if (!mqnic->ram_hw_addr) {
			ret = -ENOMEM;
			PMD_INIT_LOG(ERR, "Failed to map RAM BAR");
		}
	}


	// Check if device needs to be reset
	if (rte_read32(mqnic->hw_addr) + 4 == 0xffffffff) {
		PMD_INIT_LOG(ERR, "Device needs to be reset");
		return -EIO;
	}

	ret = mqnic_common_probe(mqnic);

	ret = eth_dev_pci_specific_init(eth_dev, bus_device);

	return ret;
}


static int
eth_mqnic_pci_probe(__rte_unused struct rte_pci_driver *pci_drv, struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *pf_ethdev;
	struct rte_eth_devargs eth_da;
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
	int retval;
	PMD_INIT_FUNC_TRACE();
	PMD_INIT_LOG(NOTICE, " Vendor: 0x%04x", pci_dev->id.vendor_id);
	PMD_INIT_LOG(NOTICE, " Device: 0x%04x", pci_dev->id.device_id);
	PMD_INIT_LOG(NOTICE, " Subsystem vendor: 0x%04x", pci_dev->id.subsystem_vendor_id);
	PMD_INIT_LOG(NOTICE, " Subsystem device: 0x%04x", pci_dev->id.subsystem_device_id);
	PMD_INIT_LOG(NOTICE, " Class: 0x%06x", pci_dev->id.class_id);

	char name[RTE_ETH_NAME_MAX_LEN];
	snprintf(name, sizeof(name), "%s.%d", pci_dev->device.name, 0);

	if (pci_dev->device.devargs) {
		retval = rte_eth_devargs_parse(pci_dev->device.devargs->args, &eth_da);
		if (retval)
			return retval;
	} else
		memset(&eth_da, 0, sizeof(eth_da));

	retval = rte_eth_dev_create(&pci_dev->device, name, sizeof(struct mqnic_priv),
					mqnic_dev_pci_specific_init, pci_dev,
					eth_mqnic_dev_init, NULL);

	if (retval) {
		return retval;
	}


	pf_ethdev = rte_eth_dev_allocated(name);
	if (pf_ethdev == NULL)
		return -ENODEV;

	/* disable uio/vfio intr/eventfd mapping */
	rte_intr_disable(intr_handle);


	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(pf_ethdev->data->dev_private);
	struct mqnic_dev *mqnic = priv->mdev;
	for (uint64_t i = 1; i < mqnic->if_count; ++i) {
		memset(name, 0, strlen(name));

		snprintf(name, sizeof(name), "%s.%ld", pci_dev->device.name, i);
		PMD_INIT_LOG(NOTICE, "Device name: %s", name);
		retval = rte_eth_dev_create(&pci_dev->device, name, sizeof(struct mqnic_priv), NULL, NULL,
						eth_mqnic_dev_init,
						mqnic);

		if (retval)
			return retval;


		pf_ethdev = rte_eth_dev_allocated(name);
		if (pf_ethdev == NULL)
			return -ENODEV;
	}

	return 0;
}

static int
eth_mqnic_dev_init(struct rte_eth_dev *dev, void *init_params)
{
	PMD_INIT_FUNC_TRACE();
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	struct mqnic_dev *mqnic = (struct mqnic_dev *)init_params;
	int ret = 0;
	if (!mqnic)
		mqnic = priv->mdev;
	else
		priv->mdev = mqnic;

	if (mqnic->initialised > 0)
		ret = mqnic_create_interface(mqnic, &mqnic->interface[mqnic->initialised], mqnic->initialised,
							mqnic->hw_addr + mqnic->initialised * mqnic->if_stride);

	struct mqnic_if *interface = mqnic->interface[mqnic->initialised];


	priv->mdev = interface->mdev;
	priv->interface = interface;
	priv->dev = dev;
	interface->dev = dev;
	interface->rx_mtu = 1500;
	interface->tx_mtu = 1500;
	priv->index = interface->index;
	priv->port_up = false;

	priv->rx_queue_count = interface->rx_queue_count;
	priv->tx_queue_count = interface->tx_queue_count;
	priv->rx_cpl_queue_count = interface->rx_cpl_queue_count;
	priv->tx_cpl_queue_count = interface->tx_cpl_queue_count;

	// associate interface resources
	priv->if_features = interface->if_features;

	/* Allocate memory for storing MAC addresses */
	dev->data->mac_addrs = rte_zmalloc(NULL, RTE_ETHER_ADDR_LEN, 0);
	dev->rx_pkt_burst = &mqnic_packet_rx;
	dev->tx_pkt_burst = &mqnic_packet_tx;
	dev->dev_ops = &mqnic_eth_dev_ops;
	if (dev->data->mac_addrs == NULL)
		return -ENOMEM;
	
	generate_random_mac(dev->data->mac_addrs);
	mqnic->initialised++;

	return ret;
}

static int
mqnic_dev_info_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{

	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	struct mqnic_dev *mqnic = priv->mdev;

	dev_info->min_rx_bufsize = 64;
	dev_info->max_rx_pktlen = priv->interface->max_rx_mtu - ETH_LEN;
	dev_info->max_rx_queues = priv->rx_queue_count;
	dev_info->max_tx_queues = priv->tx_queue_count;
	dev_info->default_rxportconf.burst_size = 32;
	dev_info->default_txportconf.burst_size = 32;
	dev_info->speed_capa = RTE_ETH_SPEED_NUM_10G;
	dev_info->default_rxportconf.nb_queues = mqnic->interface[priv->index]->rx_queue_count;
	dev_info->default_txportconf.nb_queues = mqnic->interface[priv->index]->tx_queue_count;
	dev_info->default_rxportconf.ring_size = mqnic_num_rx_queue_entries;
	dev_info->default_txportconf.ring_size = mqnic_num_tx_queue_entries;
	return 0;
}

static int
mqnic_dev_configure(__rte_unused struct rte_eth_dev *dev)
{
	return 0;
}

static int
eth_mqnic_pci_remove(struct rte_pci_device *pci_dev)
{

	struct rte_eth_dev *ethdev;

	ethdev = rte_eth_dev_allocated(pci_dev->device.name);
	if (!ethdev)
		return 0;

	rte_eth_dev_destroy(ethdev, mqnic_dev_close);
	return 0;
}

/**
 * Setup Receive queue with completion queue
 */

static int __rte_cold
mqnic_dev_rx_queue_setup(struct rte_eth_dev *dev,
				uint16_t queue_idx,
				uint16_t nb_desc,
				unsigned int socket_id,
				const struct rte_eth_rxconf *rx_conf,
				struct rte_mempool *mp)
{
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	struct mqnic_if *interface = priv->interface;
	int ret = 0;
	PMD_INIT_FUNC_TRACE();
	PMD_INIT_LOG(NOTICE, "params: queue: %d, nb_desc: %d, socket_id: %d", queue_idx, nb_desc, socket_id);

	ret = mqnic_create_cq_ring(interface, &interface->rx_cpl_ring[queue_idx], &priv->rx_cpl_ring[queue_idx],
					queue_idx,
					interface->hw_addr + interface->rx_cpl_queue_offset + 
					queue_idx * interface->rx_cpl_queue_stride);
	ret = mqnic_create_rx_ring(interface, &interface->rx_ring[queue_idx], &priv->rx_ring[queue_idx],
					queue_idx,
					interface->hw_addr + interface->rx_queue_offset + queue_idx * interface->rx_queue_stride,
					rx_conf, mp);

	priv->rx_ring[queue_idx]->mtu = priv->interface->rx_mtu;
	if (priv->interface->rx_mtu + ETH_LEN <= PAGE_SIZE)
		priv->rx_ring[queue_idx]->page_order = 0;
	else
		priv->rx_ring[queue_idx]->page_order =
			rte_log2_u32((priv->interface->rx_mtu + ETH_LEN + PAGE_SIZE) * PAGE_SIZE - 1) + 1;

	ret = mqnic_alloc_rx_ring(dev, priv->rx_ring[queue_idx], mqnic_num_rx_queue_entries, MQNIC_DESC_SIZE);
	ret = mqnic_alloc_cq_ring(dev, priv->rx_cpl_ring[queue_idx], mqnic_num_rx_queue_entries,
					MQNIC_CPL_SIZE,
					false);
	mqnic_dev_rx_queue_start(dev, queue_idx);
	return ret;
}

/*
 * Start Receive Units for specified queue.
 */
int __rte_cold
mqnic_dev_rx_queue_start(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	PMD_INIT_FUNC_TRACE();
	PMD_INIT_LOG(NOTICE, "RX Queue %d started", rx_queue_id);
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	int ret = 0;
	ret = mqnic_activate_cq_ring(priv->rx_cpl_ring[rx_queue_id], rx_queue_id);
	ret = mqnic_activate_rx_ring(dev, priv->rx_ring[rx_queue_id], rx_queue_id);
	return ret;
}

/*
 * Stop Receive Units for specified queue.
 */
int __rte_cold
mqnic_dev_rx_queue_stop(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	PMD_INIT_FUNC_TRACE();
	PMD_INIT_LOG(NOTICE, "RX Queue %d stopped", rx_queue_id);
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	mqnic_deactivate_cq_ring(priv->rx_cpl_ring[rx_queue_id]);
	mqnic_deactivate_rx_ring(priv->rx_ring[rx_queue_id]);
	return 0;
}

/**
 * Release specified queue
 */
void
mqnic_dev_rx_queue_release(struct rte_eth_dev *dev, uint16_t qid)
{
	PMD_INIT_FUNC_TRACE();
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	PMD_INIT_LOG(NOTICE, "RX Completion Queue %d released", qid);
	mqnic_destroy_cq_ring(dev, priv->rx_cpl_ring[qid], false);
	PMD_INIT_LOG(NOTICE, "RX Queue %d released", qid);
	mqnic_destroy_rx_ring(dev, priv->rx_ring[qid]);
}

/**
 * Setup Transmit queue with completion queue
 */
static int __rte_cold
mqnic_dev_tx_queue_setup(struct rte_eth_dev *dev,
				uint16_t queue_idx,
				uint16_t nb_desc,
				unsigned int socket_id,
				const struct rte_eth_txconf *tx_conf)
{
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	struct mqnic_if *interface = priv->interface;
	int ret = 0;
	PMD_INIT_FUNC_TRACE();
	PMD_INIT_LOG(NOTICE, "params: queue: %d, nb_desc: %d, socket_id: %d", queue_idx, nb_desc, socket_id);
	ret = mqnic_create_cq_ring(interface, &interface->tx_cpl_ring[queue_idx], &priv->tx_cpl_ring[queue_idx],
			queue_idx,
			interface->hw_addr + interface->tx_cpl_queue_offset +
			queue_idx * interface->tx_cpl_queue_stride);
	ret = mqnic_create_tx_ring(interface, &interface->tx_ring[queue_idx], &priv->tx_ring[queue_idx], queue_idx,
			interface->hw_addr + interface->tx_queue_offset + queue_idx * interface->tx_queue_stride,
			tx_conf);

	ret = mqnic_alloc_tx_ring(dev, priv->tx_ring[queue_idx], mqnic_num_tx_queue_entries, MQNIC_DESC_SIZE);
	ret = mqnic_alloc_cq_ring(dev, priv->tx_cpl_ring[queue_idx], mqnic_num_tx_queue_entries, MQNIC_CPL_SIZE, true);

	// Activate Queue, because an app could not call the callback
	mqnic_dev_tx_queue_start(dev, queue_idx);
	return ret;
}

/*
 * Start Transmit Units for specified queue.
 */
int __rte_cold
mqnic_dev_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id)
{
	PMD_INIT_FUNC_TRACE();
	PMD_INIT_LOG(NOTICE, "TX Queue %d started", tx_queue_id);
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	int ret = 0;
	ret = mqnic_activate_cq_ring(priv->tx_cpl_ring[tx_queue_id], tx_queue_id);
	ret = mqnic_activate_tx_ring(priv->tx_ring[tx_queue_id], tx_queue_id);
	return ret;
}

/*
 * Stop Transmit Units for specified queue.
 */
int __rte_cold
mqnic_dev_tx_queue_stop(struct rte_eth_dev *dev, uint16_t tx_queue_id)
{
	PMD_INIT_FUNC_TRACE();
	PMD_INIT_LOG(NOTICE, "TX Queue %d stopped", tx_queue_id);
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	mqnic_deactivate_cq_ring(priv->tx_cpl_ring[tx_queue_id]);
	mqnic_deactivate_tx_ring(priv->tx_ring[tx_queue_id]);
	return 0;
}

/**
 * Release specified queue
 */
void
mqnic_dev_tx_queue_release(struct rte_eth_dev *dev, uint16_t qid)
{
	PMD_INIT_FUNC_TRACE();
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	PMD_INIT_LOG(NOTICE, "TX Completion Queue %d released", qid);
	mqnic_destroy_cq_ring(dev, priv->tx_cpl_ring[qid], true);
	PMD_INIT_LOG(NOTICE, "TX Queue %d released", qid);
	mqnic_destroy_tx_ring(dev, priv->tx_ring[qid]);
}

static int
mqnic_dev_start(struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	struct rte_eth_link link;

	PMD_INIT_LOG(NOTICE, "%s on interface %d netdev %d", __func__, priv->interface->index, priv->index);

	// set MTU
	mqnic_interface_set_tx_mtu(priv->interface, priv->interface->tx_mtu + ETH_LEN);
	mqnic_interface_set_rx_mtu(priv->interface, priv->interface->rx_mtu + ETH_LEN);

	// configure RSS
	mqnic_interface_set_rx_queue_map_rss_mask(priv->interface, 0,
		rte_align32prevpow2(dev->data->nb_rx_queues) - 1);
	PMD_INIT_LOG(NOTICE, "%d", mqnic_interface_get_rx_queue_map_app_mask(priv->interface, 0));

	// enable first scheduler
	priv->sched_block[0] = priv->interface->sched_block[0];
	mqnic_activate_sched_block(priv->sched_block[0]);
	priv->port_up = true;

	memset(&link, 0, sizeof(link));
	link.link_status = RTE_ETH_LINK_UP;
	link.link_speed = RTE_ETH_SPEED_NUM_10G;
	link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	return rte_eth_linkstatus_set(dev, &link);
}

static int
mqnic_dev_stop(struct rte_eth_dev *dev)
{
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	priv->port_up = false;
	dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;
	return 0;
}

static int
mqnic_dev_link_update(__rte_unused struct rte_eth_dev *dev, __rte_unused int wait_to_complete)
{
	return 0;
}

static int
mqnic_promiscuous_enable(__rte_unused struct rte_eth_dev *dev)
{
	return 0;
}

static int
mqnic_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
	uint64_t num_packets_rx = 0;
	uint64_t num_bytes_rx = 0;
	uint64_t num_dropped_rx = 0;
	uint64_t num_packets_tx = 0;
	uint64_t num_bytes_tx = 0;
	uint64_t num_dropped_tx = 0;

	for (uint64_t i = 0; i < dev->data->nb_rx_queues; ++i) {
		num_packets_rx += priv->rx_ring[i]->packets;
		num_bytes_rx += priv->rx_ring[i]->bytes;
		num_dropped_rx += priv->rx_ring[i]->dropped_packets;
	}
	for (uint64_t i = 0; i < dev->data->nb_tx_queues; ++i) {
		num_packets_tx += priv->tx_ring[i]->packets;
		num_bytes_tx += priv->tx_ring[i]->bytes;
		num_dropped_tx += priv->tx_ring[i]->dropped_packets;
	}
	stats->ibytes = num_bytes_rx;
	stats->ipackets = num_packets_rx;
	stats->imissed = num_dropped_rx;
	stats->obytes = num_bytes_tx;
	stats->opackets = num_packets_tx;
	stats->oerrors = num_dropped_tx;
	return 0;
}

static void
mqnic_common_remove(struct mqnic_dev *mqnic)
{
	size_t k = 0;
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return;

	for (k = 0; k < ARRAY_SIZE(mqnic->interface); k++)
		if (mqnic->interface[k])
			mqnic_destroy_interface(&mqnic->interface[k]);

	if (mqnic->rb_list)
		mqnic_free_reg_block_list(mqnic->rb_list);
}

void generate_random_mac(struct rte_ether_addr *addr) {
	for (uint8_t i = 0; i < 6; ++i) {
    	uint8_t num = rand() % 256;
    	addr->addr_bytes[i] = num;
	}
}

RTE_PMD_REGISTER_PCI(net_mqnic, rte_mqnic_pmd);

RTE_LOG_REGISTER(mqnic_logtype_init, pmd.net.mqnic.init, NOTICE);
