/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) 2021-2022 Missing Link Electronics, Inc.
 * Copyright(c) 2019 The Regents of the University of California
 */

#include "rte_eth_mqnic.h"

int mqnic_create_port(struct rte_eth_dev *dev, struct mqnic_port **port_ptr, int index, uint8_t *hw_addr)
{
    struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
    struct mqnic_port *port;
    PMD_INIT_FUNC_TRACE();

    port = rte_zmalloc("ePort", sizeof(*port), RTE_CACHE_LINE_SIZE);
    if (!port)
    {
        return -ENOMEM;
    }

    *port_ptr = port;

    port->index = index;

    port->tx_queue_count = priv->tx_queue_count;

    port->hw_addr = hw_addr;
    port->dev = dev;

    // read ID registers
    PMD_INIT_LOG(NOTICE, "Port HW Addr: 0x%x", port->hw_addr);
    port->port_id = rte_read32(port->hw_addr+MQNIC_PORT_REG_PORT_ID);
    PMD_INIT_LOG(NOTICE, "Port ID: 0x%08x", port->port_id);
    port->port_features = rte_read32(port->hw_addr+MQNIC_PORT_REG_PORT_FEATURES);
    PMD_INIT_LOG(NOTICE, "Port features: 0x%08x", port->port_features);
    port->port_mtu = rte_read32(port->hw_addr+MQNIC_PORT_REG_PORT_MTU);
    PMD_INIT_LOG(NOTICE, "Port MTU: %d", port->port_mtu);

    port->sched_count = rte_read32(port->hw_addr+MQNIC_PORT_REG_SCHED_COUNT);
    PMD_INIT_LOG(NOTICE, "Scheduler count: %d", port->sched_count);
    port->sched_offset = rte_read32(port->hw_addr+MQNIC_PORT_REG_SCHED_OFFSET);
    PMD_INIT_LOG(NOTICE, "Scheduler offset: 0x%08x", port->sched_offset);
    port->sched_stride = rte_read32(port->hw_addr+MQNIC_PORT_REG_SCHED_STRIDE);
    PMD_INIT_LOG(NOTICE, "Scheduler stride: 0x%08x", port->sched_stride);
    port->sched_type = rte_read32(port->hw_addr+MQNIC_PORT_REG_SCHED_TYPE);
    PMD_INIT_LOG(NOTICE, "Scheduler type: 0x%08x", port->sched_type);

    mqnic_deactivate_port(port);

    return 0;
}

void mqnic_destroy_port(struct rte_eth_dev *dev, struct mqnic_port **port_ptr)
{
    struct mqnic_port *port = *port_ptr;
    *port_ptr = NULL;

    mqnic_deactivate_port(port);

    rte_free(port);
}

int mqnic_activate_port(struct mqnic_port *port)
{
    int k;

    // enable schedulers
    rte_write32(0xffffffff, port->hw_addr+MQNIC_PORT_REG_SCHED_ENABLE);

    // enable queues
    for (k = 0; k < port->tx_queue_count; k++)
    {
        rte_write32(3, port->hw_addr+port->sched_offset+k*4);
    }

    return 0;
}

void mqnic_deactivate_port(struct mqnic_port *port)
{
    // disable schedulers
    rte_write32(0, port->hw_addr+MQNIC_PORT_REG_SCHED_ENABLE);
}

uint32_t mqnic_port_get_rss_mask(struct mqnic_port *port)
{
    return rte_read32(port->hw_addr+MQNIC_PORT_REG_RSS_MASK);
}

void mqnic_port_set_rss_mask(struct mqnic_port *port, uint32_t rss_mask)
{
    rte_write32(rss_mask, port->hw_addr+MQNIC_PORT_REG_RSS_MASK);
}

uint32_t mqnic_port_get_tx_mtu(struct mqnic_port *port)
{
    return rte_read32(port->hw_addr+MQNIC_PORT_REG_TX_MTU);
}

void mqnic_port_set_tx_mtu(struct mqnic_port *port, uint32_t mtu)
{
    rte_write32(mtu, port->hw_addr+MQNIC_PORT_REG_TX_MTU);
}

uint32_t mqnic_port_get_rx_mtu(struct mqnic_port *port)
{
    return rte_read32(port->hw_addr+MQNIC_PORT_REG_RX_MTU);
}

void mqnic_port_set_rx_mtu(struct mqnic_port *port, uint32_t mtu)
{
    rte_write32(mtu, port->hw_addr+MQNIC_PORT_REG_RX_MTU);
}
