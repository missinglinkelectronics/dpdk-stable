/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) 2021-2022 Missing Link Electronics, Inc.
 */

#include "rte_eth_mqnic.h"
#include <linux/if_packet.h>

#define mqnic_VENDOR_ID 0x1234
#define mqnic_DEV_ID 0x1001

static int mqnic_dev_configure(struct rte_eth_dev *dev);
static int eth_mqnic_pci_remove(struct rte_pci_device *pci_dev);
static int eth_mqnic_pci_probe(struct rte_pci_driver *pci_drv __rte_unused, struct rte_pci_device *pci_dev);
static int mqnic_dev_info_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info);
static int eth_mqnic_dev_init(struct rte_eth_dev *eth_dev, void *init_params __rte_unused);
static int __rte_cold mqnic_dev_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc, unsigned int socket_id, const struct rte_eth_rxconf *rx_conf, struct rte_mempool *mp);
static int __rte_cold mqnic_dev_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc, unsigned int socket_id, const struct rte_eth_txconf *tx_conf);
static int mqnic_dev_start(struct rte_eth_dev *dev);
static int mqnic_dev_stop(struct rte_eth_dev *dev);
static int mqnic_dev_link_update(struct rte_eth_dev *dev, int wait_to_complete);

static int mqnic_promiscuous_enable(struct rte_eth_dev *dev);

static uint16_t
mqnic_packet_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts){
	struct mqnic_ring *pkt_q = queue;
    int packets_read = mqnic_process_rx_cq(pkt_q, nb_pkts, bufs);
	return packets_read;

}

static uint16_t
mqnic_packet_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts){
    struct mqnic_ring *pkt_q = queue;
    mqnic_process_tx_cq(pkt_q, bufs, nb_pkts);
    int packets_send = mqnic_start_xmit(pkt_q, bufs, nb_pkts);
    return packets_send;
}

/*
 * Reset and stop device.
 */
static int
mqnic_dev_close(struct rte_eth_dev *dev){
    struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
    mqnic_destroy_rx_ring(dev, &priv->rx_ring[0]);
    mqnic_destroy_cq_ring(dev, &priv->rx_cpl_ring[0], false);
    mqnic_destroy_tx_ring(dev, &priv->tx_ring[0]);
    mqnic_destroy_cq_ring(dev, &priv->tx_cpl_ring[0], true);
    for (uint8_t k = 0; k < priv->port_count; k++)
    {
        if (priv->ports[k])
        {
            mqnic_destroy_port(dev, &priv->ports[k]);
        }
    }
    return 0;
}

static int
mqnic_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
    struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
    priv->max_mtu = mtu;
    return 0;
}

/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id pci_id_mqnic_map[] = {
	{ RTE_PCI_DEVICE(mqnic_VENDOR_ID, mqnic_DEV_ID) },
	{ .vendor_id = 0, /* sentinel */ },
};

static const struct eth_dev_ops mqnic_eth_dev_ops = {
	.dev_configure        = mqnic_dev_configure,
    .dev_infos_get        = mqnic_dev_info_get,
	.rx_queue_setup       = mqnic_dev_rx_queue_setup,
	.tx_queue_setup       = mqnic_dev_tx_queue_setup,
	.dev_start            = mqnic_dev_start,
	.dev_stop             = mqnic_dev_stop,
	.link_update          = mqnic_dev_link_update,
    .promiscuous_enable   = mqnic_promiscuous_enable,
    .dev_close            = mqnic_dev_close,
    .mtu_set              = mqnic_dev_mtu_set,
};

static struct rte_pci_driver rte_mqnic_pmd = {
	.id_table = pci_id_mqnic_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = eth_mqnic_pci_probe,
	.remove = eth_mqnic_pci_remove,
};



static inline int
mqnic_dev_pci_specific_init(struct rte_eth_dev *eth_dev, void *bus_device) {

	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct mqnic_hw *hw = MQNIC_DEV_PRIVATE_TO_HW(eth_dev->data->dev_private);

	PMD_INIT_FUNC_TRACE();

    eth_dev->dev_ops = &mqnic_eth_dev_ops;

	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;
	hw->hw_addr = (void *)pci_dev->mem_resource[0].addr;

	// Read BAR Registers
	PMD_INIT_LOG(NOTICE,"Read Bar registers");
	hw->fw_id = rte_read32(hw->hw_addr + MQNIC_REG_FW_ID);
	PMD_INIT_LOG(NOTICE,"FW ID: 0x%08x", hw->fw_id);
	hw->fw_ver = rte_read32(hw->hw_addr + MQNIC_REG_FW_VER);
	PMD_INIT_LOG(NOTICE, "FW version: %d.%d", hw->fw_ver >> 16, hw->fw_ver & 0xffff);
	hw->board_id = rte_read32(hw->hw_addr + MQNIC_REG_BOARD_ID);
	PMD_INIT_LOG(NOTICE, "Board ID: 0x%08x", hw->board_id);
	hw->board_ver = rte_read32(hw->hw_addr + MQNIC_REG_BOARD_VER);
	PMD_INIT_LOG(NOTICE, "Board version: %d.%d", hw->board_ver >> 16, hw->board_ver & 0xffff);
	hw->phc_count = rte_read32(hw->hw_addr + MQNIC_REG_PHC_COUNT);
	PMD_INIT_LOG(NOTICE,"PHC count: %d", hw->phc_count );
	hw->phc_offset = rte_read32(hw->hw_addr + MQNIC_REG_PHC_OFFSET);
	PMD_INIT_LOG(NOTICE, "PHC offset: 0x%08x", hw->phc_offset);
	hw->phc_offset = rte_read32(hw->hw_addr + MQNIC_REG_PHC_STRIDE);
	PMD_INIT_LOG(NOTICE, "PHC Stride: 0x%08x", hw->phc_stride);
	hw->if_count = rte_read32(hw->hw_addr + MQNIC_REG_IF_COUNT);
	PMD_INIT_LOG(NOTICE, "IF count: %d", hw->if_count);
	hw->if_csr_offset = rte_read32(hw->hw_addr + MQNIC_REG_IF_CSR_OFFSET);
    PMD_INIT_LOG(NOTICE, "IF CSR offset: 0x%08x", hw->if_csr_offset);
	hw->if_stride = rte_read32(hw->hw_addr + MQNIC_REG_IF_STRIDE);
    PMD_INIT_LOG(NOTICE, "IF stride: 0x%08x", hw->if_stride);

	int ret = eth_dev_pci_specific_init(eth_dev, bus_device);
		if(ret != 0) {
		return ret;
	}

	return ret;
}


static int
eth_mqnic_pci_probe(struct rte_pci_driver *pci_drv __rte_unused, struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *pf_ethdev;
	struct rte_eth_devargs eth_da;
    struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
    int retval;

	PMD_INIT_FUNC_TRACE();

	PMD_INIT_LOG(NOTICE, "Board ID: 0x%08x", rte_read32((uint8_t *)pci_dev->mem_resource[0].addr+MQNIC_REG_BOARD_ID));

	if (pci_dev->device.devargs) {
		retval = rte_eth_devargs_parse(pci_dev->device.devargs->args, &eth_da);
		if (retval)
			return retval;
	} else
		memset(&eth_da, 0, sizeof(eth_da));

	retval = rte_eth_dev_create(&pci_dev->device, pci_dev->device.name,
		sizeof(struct mqnic_adapter),
		mqnic_dev_pci_specific_init, pci_dev,
		eth_mqnic_dev_init, NULL);

	if (retval || eth_da.nb_representor_ports < 1)
		return retval;

	pf_ethdev = rte_eth_dev_allocated(pci_dev->device.name);
	if (pf_ethdev == NULL)
		return -ENODEV;

    /* disable uio/vfio intr/eventfd mapping */
	rte_intr_disable(intr_handle);

	return 0;
}

static int eth_mqnic_dev_init(struct rte_eth_dev *eth_dev, void *init_params __rte_unused)
{
	struct mqnic_hw *hw = MQNIC_DEV_PRIVATE_TO_HW(eth_dev->data->dev_private);
	struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(eth_dev->data->dev_private);
	int ret = 0;
    uint32_t k;

	PMD_INIT_FUNC_TRACE();
    priv->csr_hw_addr = hw->hw_addr + hw->if_csr_offset + hw->if_stride;
    priv->hw_addr = hw->hw_addr + hw->if_stride;
	priv->port_up = false;

	PMD_INIT_LOG(NOTICE, "Address of fuction and interface: %p %p", hw, priv);
	PMD_INIT_LOG(NOTICE, "Address of fuction and interface: %p 0x%08x", hw->hw_addr,hw->if_csr_offset);
	PMD_INIT_LOG(NOTICE, "CSR Hardware address: %p", priv->csr_hw_addr);
    PMD_INIT_LOG(NOTICE, "CSR Hardware address: %p", priv->hw_addr);
	// read ID registers
    priv->if_id = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_IF_ID);
    PMD_INIT_LOG(NOTICE, "IF ID: 0x%08x", priv->if_id);
    priv->if_features = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_IF_FEATURES);
    PMD_INIT_LOG(NOTICE, "IF features: 0x%08x", priv->if_features);

    priv->event_queue_count = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_EVENT_QUEUE_COUNT);
    PMD_INIT_LOG(NOTICE, "Event queue count: %d", priv->event_queue_count);
    priv->event_queue_offset = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_EVENT_QUEUE_OFFSET);
    PMD_INIT_LOG(NOTICE, "Event queue offset: 0x%08x", priv->event_queue_offset);
    priv->tx_queue_count = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_TX_QUEUE_COUNT);
    PMD_INIT_LOG(NOTICE, "TX queue count: %d", priv->tx_queue_count);
    priv->tx_queue_offset = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_TX_QUEUE_OFFSET);
    PMD_INIT_LOG(NOTICE, "TX queue offset: 0x%08x", priv->tx_queue_offset);
    priv->tx_cpl_queue_count = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_TX_CPL_QUEUE_COUNT);
    PMD_INIT_LOG(NOTICE, "TX completion queue count: %d", priv->tx_cpl_queue_count);
    priv->tx_cpl_queue_offset = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_TX_CPL_QUEUE_OFFSET);
    PMD_INIT_LOG(NOTICE, "TX completion queue offset: 0x%08x", priv->tx_cpl_queue_offset);
    priv->rx_queue_count = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_RX_QUEUE_COUNT);
    PMD_INIT_LOG(NOTICE, "RX queue count: %d", priv->rx_queue_count);
    priv->rx_queue_offset = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_RX_QUEUE_OFFSET);
    PMD_INIT_LOG(NOTICE, "RX queue offset: 0x%08x", priv->rx_queue_offset);
    priv->rx_cpl_queue_count = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_RX_CPL_QUEUE_COUNT);
    PMD_INIT_LOG(NOTICE, "RX completion queue count: %d", priv->rx_cpl_queue_count);
    priv->rx_cpl_queue_offset = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_RX_CPL_QUEUE_OFFSET);
    PMD_INIT_LOG(NOTICE, "RX completion queue offset: 0x%08x", priv->rx_cpl_queue_offset);
    priv->port_count = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_PORT_COUNT);
    PMD_INIT_LOG(NOTICE, "Port count: %d", priv->port_count);
    priv->port_offset = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_PORT_OFFSET);
    PMD_INIT_LOG(NOTICE, "Port offset: 0x%08x", priv->port_offset);
    priv->port_stride = rte_read32(priv->csr_hw_addr+MQNIC_IF_REG_PORT_STRIDE);
    PMD_INIT_LOG(NOTICE, "Port stride: 0x%08x", priv->port_stride);

    if (priv->event_queue_count > MQNIC_MAX_EVENT_RINGS)
        priv->event_queue_count = MQNIC_MAX_EVENT_RINGS;
    if (priv->tx_queue_count > MQNIC_MAX_TX_RINGS)
        priv->tx_queue_count = MQNIC_MAX_TX_RINGS;
    if (priv->tx_cpl_queue_count > MQNIC_MAX_TX_CPL_RINGS)
        priv->tx_cpl_queue_count = MQNIC_MAX_TX_CPL_RINGS;
    if (priv->rx_queue_count > MQNIC_MAX_RX_RINGS)
        priv->rx_queue_count = MQNIC_MAX_RX_RINGS;
    if (priv->rx_cpl_queue_count > MQNIC_MAX_RX_CPL_RINGS)
        priv->rx_cpl_queue_count = MQNIC_MAX_RX_CPL_RINGS;

    if (priv->port_count > MQNIC_MAX_PORTS)
        priv->port_count = MQNIC_MAX_PORTS;

    // Set max MTU
    priv->max_mtu = 1500;

    rte_write32(0xf << 8, priv->hw_addr+priv->tx_queue_offset+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
    priv->max_desc_block_size = 1 << ((rte_read32(priv->hw_addr+priv->tx_queue_offset+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG) >> 8) & 0xf);
    rte_write32(0, priv->hw_addr+priv->tx_queue_offset+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);

    priv->max_desc_block_size = priv->max_desc_block_size < MQNIC_MAX_FRAGS ? priv->max_desc_block_size : MQNIC_MAX_FRAGS;

	for (k = 0; k < priv->port_count; k++)
    {
        ret = mqnic_create_port(eth_dev, &priv->ports[k], k, priv->hw_addr+priv->port_offset+k*priv->port_stride);
        if (ret)
        {
            return -42;
        }

        mqnic_port_set_rss_mask(priv->ports[k], 0x00000000);
    }

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("mqnic_mac_addr", RTE_ETHER_ADDR_LEN, 0);
    eth_dev->rx_pkt_burst = &mqnic_packet_rx;
    eth_dev->tx_pkt_burst = &mqnic_packet_tx;
	if (eth_dev->data->mac_addrs == NULL) {
		return -ENOMEM;
	}

    return 0;
}

static int
mqnic_dev_info_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{

	struct mqnic_ifhw *priv_mqnic_ifhw = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
	dev_info->max_rx_queues = priv_mqnic_ifhw->rx_queue_count;
	dev_info->max_tx_queues = priv_mqnic_ifhw->tx_queue_count;

	return 0;
}

static int
mqnic_dev_configure(struct rte_eth_dev *dev)
{

	return 0;
}

static int eth_mqnic_pci_remove(struct rte_pci_device *pci_dev)
{

    struct rte_eth_dev *ethdev;

	ethdev = rte_eth_dev_allocated(pci_dev->device.name);
	if (!ethdev)
		return 0;

    rte_eth_dev_destroy(ethdev, mqnic_dev_close);
    return 0;
}

static int __rte_cold mqnic_dev_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc, unsigned int socket_id, const struct rte_eth_rxconf *rx_conf, struct rte_mempool *mp)
{
	struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
	PMD_INIT_FUNC_TRACE();
	PMD_INIT_LOG(NOTICE, "params: queue: %d, nb_desc: %d, socket_id: %d", queue_idx, nb_desc, socket_id);

    mqnic_create_rx_ring(dev, queue_idx, nb_desc, socket_id, rx_conf, mp);
    mqnic_create_cq_ring(dev, queue_idx, nb_desc, socket_id, mp, false);

    priv->rx_ring[queue_idx]->mtu = priv->max_mtu;
    if (priv->max_mtu + ETH_LEN <= PAGE_SIZE){
        priv->rx_ring[queue_idx]->page_order = 0;
    } else {
        priv->rx_ring[queue_idx]->page_order = rte_log2_u32((priv->max_mtu + ETH_LEN + PAGE_SIZE) * PAGE_SIZE - 1) + 1;
    }
    mqnic_activate_cq_ring(dev, priv->rx_cpl_ring[queue_idx], queue_idx);
    mqnic_activate_rx_ring(dev, priv->rx_ring[queue_idx], queue_idx);
	return 0;
}
static int __rte_cold mqnic_dev_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc, unsigned int socket_id, const struct rte_eth_txconf *tx_conf)
{
    struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
    PMD_INIT_FUNC_TRACE();
	PMD_INIT_LOG(NOTICE, "params: queue: %d, nb_desc: %d, socket_id: %d", queue_idx, nb_desc, socket_id);
    mqnic_create_cq_ring(dev, queue_idx, nb_desc, socket_id, NULL, true);
	mqnic_create_tx_ring(dev, queue_idx, nb_desc, socket_id, tx_conf);
    mqnic_activate_cq_ring(dev, priv->tx_cpl_ring[queue_idx], queue_idx);
    mqnic_activate_tx_ring(dev, priv->tx_ring[queue_idx], queue_idx);
	return 0;
}

static int mqnic_dev_start(struct rte_eth_dev *dev)
{

    struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
	PMD_INIT_FUNC_TRACE();
    PMD_INIT_LOG(NOTICE, "mqnic start on port %d", priv->port);

    // configure ports
    for (uint32_t k = 0; k < priv->port_count; k++)
    {
        mqnic_port_set_rx_mtu(priv->ports[0], priv->max_mtu + ETH_LEN);
        mqnic_port_set_tx_mtu(priv->ports[0], priv->max_mtu + ETH_LEN);
    }

    // enable first port
    mqnic_activate_port(priv->ports[0]);

    priv->port_up = true;
	dev->data->dev_link.link_status = ETH_LINK_UP;
	return 0;
}

static int mqnic_dev_stop(struct rte_eth_dev *dev)
{
    struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
    mqnic_deactivate_port(priv->ports[0]);
    priv->port_up = true;
	dev->data->dev_link.link_status = ETH_LINK_UP;
    return 0;
}

static int mqnic_dev_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
	return 0;
}

static int mqnic_promiscuous_enable(struct rte_eth_dev *dev){
    return 0;
}

RTE_PMD_REGISTER_PCI(net_mqnic, rte_mqnic_pmd);

RTE_LOG_REGISTER(mqnic_logtype_init, pmd.net.mqnic.init, NOTICE);
