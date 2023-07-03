/* SPDX-License-Identifier: BSD-2-Clause-views
 * Copyright(c) 2021-2023 Missing Link Electronics, Inc.
 * Copyright(c) 2019 The Regents of the University of California
 */

#include "rte_eth_mqnic.h"

int
mqnic_create_interface(struct mqnic_dev *mdev, struct mqnic_if **interface_ptr, int index, uint8_t *hw_addr)
{
	PMD_INIT_FUNC_TRACE();
	struct mqnic_if *interface;
	struct mqnic_reg_block *rb;
	int ret = 0;
	uint32_t k;

	interface = rte_zmalloc(NULL, sizeof(*interface), RTE_CACHE_LINE_SIZE);
	if (!interface)
		return -ENOMEM;

	*interface_ptr = interface;

	interface->mdev = mdev;

	interface->index = index;

	interface->hw_regs_size = mdev->if_stride;
	interface->hw_addr = hw_addr;
	interface->csr_hw_addr = hw_addr + mdev->if_csr_offset;

	// Enumerate registers
	interface->rb_list =
		mqnic_enumerate_reg_block_list(interface->hw_addr, mdev->if_csr_offset, interface->hw_regs_size);
	if (!interface->rb_list) {
		ret = -EIO;
		PMD_INIT_LOG(ERR, "Failed to enumerate blocks");
		goto fail;
	}

	PMD_INIT_LOG(NOTICE, "Interface-level register blocks:");
	for (rb = interface->rb_list; rb->regs; rb++)
		PMD_INIT_LOG(NOTICE, " type 0x%08x (v %d.%d.%d.%d)", rb->type, rb->version >> 24,
				(rb->version >> 16) & 0xff,
				(rb->version >> 8) & 0xff, rb->version & 0xff);

	interface->if_ctrl_rb = mqnic_find_reg_block(interface->rb_list, MQNIC_RB_IF_CTRL_TYPE,
							MQNIC_RB_IF_CTRL_VER, 0);

	if (!interface->if_ctrl_rb) {
		ret = -EIO;
		PMD_INIT_LOG(ERR, "Interface control block not found");
		goto fail;
	}

	interface->if_features = rte_read32(interface->if_ctrl_rb->regs + MQNIC_RB_IF_CTRL_REG_FEATURES);
	interface->port_count = rte_read32(interface->if_ctrl_rb->regs + MQNIC_RB_IF_CTRL_REG_PORT_COUNT);
	interface->sched_block_count = rte_read32(interface->if_ctrl_rb->regs + MQNIC_RB_IF_CTRL_REG_SCHED_COUNT);
	interface->max_tx_mtu = rte_read32(interface->if_ctrl_rb->regs + MQNIC_RB_IF_CTRL_REG_MAX_TX_MTU);
	interface->max_rx_mtu = rte_read32(interface->if_ctrl_rb->regs + MQNIC_RB_IF_CTRL_REG_MAX_RX_MTU);

	PMD_INIT_LOG(NOTICE, "IF features: 0x%08x", interface->if_features);
	PMD_INIT_LOG(NOTICE, "Port count: %d", interface->port_count);
	PMD_INIT_LOG(NOTICE, "Scheduler block count: %d", interface->sched_block_count);
	PMD_INIT_LOG(NOTICE, "Max TX MTU: %d", interface->max_tx_mtu);
	PMD_INIT_LOG(NOTICE, "Max RX MTU: %d", interface->max_rx_mtu);

	interface->tx_queue_rb = mqnic_find_reg_block(interface->rb_list, MQNIC_RB_TX_QM_TYPE, MQNIC_RB_TX_QM_VER, 0);

	if (!interface->tx_queue_rb) {
		ret = -EIO;
		PMD_INIT_LOG(ERR, "TX queue block not found");
		goto fail;
	}

	interface->tx_queue_offset = rte_read32(interface->tx_queue_rb->regs + MQNIC_RB_TX_QM_REG_OFFSET);
	interface->tx_queue_count = rte_read32(interface->tx_queue_rb->regs + MQNIC_RB_TX_QM_REG_COUNT);
	interface->tx_queue_stride = rte_read32(interface->tx_queue_rb->regs + MQNIC_RB_TX_QM_REG_STRIDE);

	PMD_INIT_LOG(NOTICE, "TX queue offset: 0x%08x", interface->tx_queue_offset);
	PMD_INIT_LOG(NOTICE, "TX queue count: %d", interface->tx_queue_count);
	PMD_INIT_LOG(NOTICE, "TX queue stride: 0x%08x", interface->tx_queue_stride);

	interface->tx_queue_count = RTE_MIN(interface->tx_queue_count, (uint32_t)MQNIC_MAX_TX_RINGS);

	interface->tx_cpl_queue_rb = mqnic_find_reg_block(interface->rb_list, MQNIC_RB_TX_CQM_TYPE,
								MQNIC_RB_TX_CQM_VER,
								0);

	if (!interface->tx_cpl_queue_rb) {
		ret = -EIO;
		PMD_INIT_LOG(ERR, "TX completion queue block not found");
		goto fail;
	}

	interface->tx_cpl_queue_offset = rte_read32(interface->tx_cpl_queue_rb->regs + MQNIC_RB_TX_CQM_REG_OFFSET);
	interface->tx_cpl_queue_count = rte_read32(interface->tx_cpl_queue_rb->regs + MQNIC_RB_TX_CQM_REG_COUNT);
	interface->tx_cpl_queue_stride = rte_read32(interface->tx_cpl_queue_rb->regs + MQNIC_RB_TX_CQM_REG_STRIDE);

	PMD_INIT_LOG(NOTICE, "TX completion queue offset: 0x%08x", interface->tx_cpl_queue_offset);
	PMD_INIT_LOG(NOTICE, "TX completion queue count: %d", interface->tx_cpl_queue_count);
	PMD_INIT_LOG(NOTICE, "TX completion queue stride: 0x%08x", interface->tx_cpl_queue_stride);

	interface->tx_cpl_queue_count = RTE_MIN(interface->tx_cpl_queue_count, (uint32_t)MQNIC_MAX_TX_CPL_RINGS);

	interface->rx_queue_rb = mqnic_find_reg_block(interface->rb_list, MQNIC_RB_RX_QM_TYPE, MQNIC_RB_RX_QM_VER, 0);

	if (!interface->rx_queue_rb) {
		ret = -EIO;
		PMD_INIT_LOG(ERR, "RX queue block not found");
		goto fail;
	}

	interface->rx_queue_offset = rte_read32(interface->rx_queue_rb->regs + MQNIC_RB_RX_QM_REG_OFFSET);
	interface->rx_queue_count = rte_read32(interface->rx_queue_rb->regs + MQNIC_RB_RX_QM_REG_COUNT);
	interface->rx_queue_stride = rte_read32(interface->rx_queue_rb->regs + MQNIC_RB_RX_QM_REG_STRIDE);

	PMD_INIT_LOG(NOTICE, "RX queue offset: 0x%08x", interface->rx_queue_offset);
	PMD_INIT_LOG(NOTICE, "RX queue count: %d", interface->rx_queue_count);
	PMD_INIT_LOG(NOTICE, "RX queue stride: 0x%08x", interface->rx_queue_stride);

	interface->rx_queue_count = RTE_MIN(interface->rx_queue_count, (uint32_t)MQNIC_MAX_RX_RINGS);

	interface->rx_cpl_queue_rb = mqnic_find_reg_block(interface->rb_list, MQNIC_RB_RX_CQM_TYPE,
								MQNIC_RB_RX_CQM_VER,
								0);

	if (!interface->rx_cpl_queue_rb) {
		ret = -EIO;
		PMD_INIT_LOG(ERR, "RX completion queue block not found");
		goto fail;
	}

	interface->rx_cpl_queue_offset = rte_read32(interface->rx_cpl_queue_rb->regs + MQNIC_RB_RX_CQM_REG_OFFSET);
	interface->rx_cpl_queue_count = rte_read32(interface->rx_cpl_queue_rb->regs + MQNIC_RB_RX_CQM_REG_COUNT);
	interface->rx_cpl_queue_stride = rte_read32(interface->rx_cpl_queue_rb->regs + MQNIC_RB_RX_CQM_REG_STRIDE);

	PMD_INIT_LOG(NOTICE, "RX completion queue offset: 0x%08x", interface->rx_cpl_queue_offset);
	PMD_INIT_LOG(NOTICE, "RX completion queue count: %d", interface->rx_cpl_queue_count);
	PMD_INIT_LOG(NOTICE, "RX completion queue stride: 0x%08x", interface->rx_cpl_queue_stride);

	interface->rx_cpl_queue_count = RTE_MIN(interface->rx_cpl_queue_count, (uint32_t)MQNIC_MAX_RX_CPL_RINGS);

	interface->rx_queue_map_rb =
		mqnic_find_reg_block(interface->rb_list, MQNIC_RB_RX_QUEUE_MAP_TYPE, MQNIC_RB_RX_QUEUE_MAP_VER, 0);

	if (!interface->rx_queue_map_rb) {
		ret = -EIO;
		PMD_INIT_LOG(ERR, "RX queue map block not found");
		goto fail;
	}

	for (k = 0; k < interface->port_count; k++) {
		mqnic_interface_set_rx_queue_map_offset(interface, k, 0);
		mqnic_interface_set_rx_queue_map_rss_mask(interface, k, 0);
		mqnic_interface_set_rx_queue_map_app_mask(interface, k, 0);
	}

	// determine desc block size
	rte_write32(0xf << 8, hw_addr + interface->tx_queue_offset + MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
	interface->max_desc_block_size =
		1 << ((rte_read32(hw_addr + interface->tx_queue_offset + MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG) >> 8) & 0xf);
	rte_write32(0, hw_addr + interface->tx_queue_offset + MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);

	PMD_INIT_LOG(NOTICE, "Max desc block size: %d", interface->max_desc_block_size);

	interface->max_desc_block_size = RTE_MIN(interface->max_desc_block_size, (uint32_t)MQNIC_MAX_FRAGS);

	// create ports
	for (k = 0; k < interface->port_count; k++) {
		struct mqnic_reg_block *port_rb =
			mqnic_find_reg_block(interface->rb_list, MQNIC_RB_PORT_TYPE, MQNIC_RB_PORT_VER, k);

		if (!port_rb) {
			ret = -EIO;
			PMD_INIT_LOG(ERR, "Port index %d not found", k);
			goto fail;
		}

		ret = mqnic_create_port(interface, &interface->port[k], k, port_rb);
		if (ret)
			goto fail;
	}

	// create ports
	interface->dev_port_base = mdev->dev_port_max;
	interface->dev_port_max = mdev->dev_port_max;

	// create schedulers
	for (k = 0; k < interface->sched_block_count; k++) {
		struct mqnic_reg_block *sched_block_rb =
			mqnic_find_reg_block(interface->rb_list, MQNIC_RB_SCHED_BLOCK_TYPE, MQNIC_RB_SCHED_BLOCK_VER, k);

		if (!sched_block_rb) {
			ret = -EIO;
			PMD_INIT_LOG(ERR, "Scheduler block index %d not found", k);
			goto fail;
		}

		ret = mqnic_create_sched_block(interface, &interface->sched_block[k], k, sched_block_rb);
		if (ret)
			goto fail;
	}

	return 0;

fail:
	mqnic_destroy_interface(interface_ptr);
	return ret;
}

void
mqnic_destroy_interface(struct mqnic_if **interface_ptr)
{
	struct mqnic_if *interface = *interface_ptr;
	uint32_t k;

	// free rings
	for (k = 0; k < ARRAY_SIZE(interface->tx_ring); k++)
		if (interface->tx_ring[k])
			mqnic_destroy_tx_ring(interface->dev, interface->tx_ring[k]);

	for (k = 0; k < ARRAY_SIZE(interface->tx_cpl_ring); k++)
		if (interface->tx_cpl_ring[k])
			mqnic_destroy_cq_ring(interface->dev, interface->tx_cpl_ring[k], true);

	for (k = 0; k < ARRAY_SIZE(interface->rx_ring); k++)
		if (interface->rx_ring[k])
			mqnic_destroy_rx_ring(interface->dev, interface->rx_ring[k]);

	for (k = 0; k < ARRAY_SIZE(interface->rx_cpl_ring); k++)
		if (interface->rx_cpl_ring[k])
			mqnic_destroy_cq_ring(interface->dev, interface->rx_cpl_ring[k], false);

	// free schedulers
	for (k = 0; k < ARRAY_SIZE(interface->sched_block); k++)
		if (interface->sched_block[k])
			mqnic_destroy_sched_block(&interface->sched_block[k]);

	// free ports
	for (k = 0; k < ARRAY_SIZE(interface->port); k++)
		if (interface->port[k])
			mqnic_destroy_port(&interface->port[k]);

	if (interface->rb_list)
		mqnic_free_reg_block_list(interface->rb_list);

	rte_free(interface);
	*interface_ptr = NULL;
}

uint32_t
mqnic_interface_get_tx_mtu(struct mqnic_if *interface)
{
	return rte_read32(interface->if_ctrl_rb->regs + MQNIC_RB_IF_CTRL_REG_TX_MTU);
}

void
mqnic_interface_set_tx_mtu(struct mqnic_if *interface, uint32_t mtu)
{
	rte_write32(mtu, interface->if_ctrl_rb->regs + MQNIC_RB_IF_CTRL_REG_TX_MTU);
}

uint32_t
mqnic_interface_get_rx_mtu(struct mqnic_if *interface)
{
	return rte_read32(interface->if_ctrl_rb->regs + MQNIC_RB_IF_CTRL_REG_RX_MTU);
}

void
mqnic_interface_set_rx_mtu(struct mqnic_if *interface, uint32_t mtu)
{
	rte_write32(mtu, interface->if_ctrl_rb->regs + MQNIC_RB_IF_CTRL_REG_RX_MTU);
}

uint32_t
mqnic_interface_get_rx_queue_map_offset(struct mqnic_if *interface, int port)
{
	return rte_read32(interface->rx_queue_map_rb->regs + MQNIC_RB_RX_QUEUE_MAP_CH_OFFSET +
				MQNIC_RB_RX_QUEUE_MAP_CH_STRIDE * port +
				MQNIC_RB_RX_QUEUE_MAP_CH_REG_OFFSET);
}

void
mqnic_interface_set_rx_queue_map_offset(struct mqnic_if *interface, int port, uint32_t val)
{
	rte_write32(val, interface->rx_queue_map_rb->regs + MQNIC_RB_RX_QUEUE_MAP_CH_OFFSET +
			MQNIC_RB_RX_QUEUE_MAP_CH_STRIDE * port + MQNIC_RB_RX_QUEUE_MAP_CH_REG_OFFSET);
}

uint32_t
mqnic_interface_get_rx_queue_map_rss_mask(struct mqnic_if *interface, int port)
{
	return rte_read32(interface->rx_queue_map_rb->regs + MQNIC_RB_RX_QUEUE_MAP_CH_OFFSET +
				MQNIC_RB_RX_QUEUE_MAP_CH_STRIDE * port +
				MQNIC_RB_RX_QUEUE_MAP_CH_REG_RSS_MASK);
}

void
mqnic_interface_set_rx_queue_map_rss_mask(struct mqnic_if *interface, int port, uint32_t val)
{
	rte_write32(val, interface->rx_queue_map_rb->regs + MQNIC_RB_RX_QUEUE_MAP_CH_OFFSET +
			MQNIC_RB_RX_QUEUE_MAP_CH_STRIDE * port + MQNIC_RB_RX_QUEUE_MAP_CH_REG_RSS_MASK);
}

uint32_t
mqnic_interface_get_rx_queue_map_app_mask(struct mqnic_if *interface, int port)
{
	return rte_read32(interface->rx_queue_map_rb->regs + MQNIC_RB_RX_QUEUE_MAP_CH_OFFSET +
				MQNIC_RB_RX_QUEUE_MAP_CH_STRIDE * port +
				MQNIC_RB_RX_QUEUE_MAP_CH_REG_APP_MASK);
}

void
mqnic_interface_set_rx_queue_map_app_mask(struct mqnic_if *interface, int port, uint32_t val)
{
	rte_write32(val, interface->rx_queue_map_rb->regs + MQNIC_RB_RX_QUEUE_MAP_CH_OFFSET +
			MQNIC_RB_RX_QUEUE_MAP_CH_STRIDE * port + MQNIC_RB_RX_QUEUE_MAP_CH_REG_APP_MASK);
}
