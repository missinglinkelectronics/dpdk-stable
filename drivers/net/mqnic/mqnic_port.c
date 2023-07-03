/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) 2021-2023 Missing Link Electronics, Inc.
 * Copyright(c) 2019 The Regents of the University of California
 */

#include "rte_eth_mqnic.h"

int
mqnic_create_port(struct mqnic_if *interface, struct mqnic_port **port_ptr, int index, struct mqnic_reg_block *port_rb)
{
	struct rte_eth_dev *dev = interface->dev;
	struct mqnic_port *port;
	struct mqnic_reg_block *rb;
	uint32_t offset;
	int ret = 0;

	port = rte_zmalloc(NULL, sizeof(*port), RTE_CACHE_LINE_SIZE);
	if (!port)
		return -ENOMEM;

	*port_ptr = port;

	port->dev = dev;
	port->interface = interface;

	port->index = index;

	port->port_rb = port_rb;

	offset = rte_read32(port_rb->regs + MQNIC_RB_SCHED_BLOCK_REG_OFFSET);

	port->rb_list = mqnic_enumerate_reg_block_list(interface->hw_addr, offset, interface->hw_regs_size - offset);

	if (!port->rb_list) {
		ret = -EIO;
		PMD_INIT_LOG(ERR, "Failed to enumerate blocks");
		goto fail;
	}

	PMD_INIT_LOG(NOTICE, "Port-level register blocks:");
	for (rb = port->rb_list; rb->regs; rb++)
		PMD_INIT_LOG(NOTICE, " type 0x%08x (v %d.%d.%d.%d)", rb->type, rb->version >> 24, (rb->version >> 16) & 0xff,
					 (rb->version >> 8) & 0xff, rb->version & 0xff);

	port->port_ctrl_rb = mqnic_find_reg_block(port->rb_list, MQNIC_RB_PORT_CTRL_TYPE, MQNIC_RB_PORT_CTRL_VER, 0);

	if (!port->port_ctrl_rb) {
		ret = -EIO;
		PMD_INIT_LOG(ERR, "Port control register block not found");
		goto fail;
	}

	port->port_features = rte_read32(port->port_ctrl_rb->regs + MQNIC_RB_PORT_CTRL_REG_FEATURES);

	PMD_INIT_LOG(NOTICE, "Port features: 0x%08x", port->port_features);

	PMD_INIT_LOG(NOTICE, "Port TX status: 0x%08x", mqnic_port_get_tx_status(port));
	PMD_INIT_LOG(NOTICE, "Port RX status: 0x%08x", mqnic_port_get_rx_status(port));

	return 0;

fail:
	mqnic_destroy_port(port_ptr);
	return ret;
}

void
mqnic_destroy_port(struct mqnic_port **port_ptr)
{
	struct mqnic_port *port = *port_ptr;

	if (port->rb_list)
		mqnic_free_reg_block_list(port->rb_list);

	rte_free(port);
	*port_ptr = NULL;
}

uint32_t
mqnic_port_get_tx_status(struct mqnic_port *port)
{
	return rte_read32(port->port_ctrl_rb->regs + MQNIC_RB_PORT_CTRL_REG_TX_STATUS);
}

uint32_t
mqnic_port_get_rx_status(struct mqnic_port *port)
{
	return rte_read32(port->port_ctrl_rb->regs + MQNIC_RB_PORT_CTRL_REG_RX_STATUS);
}
