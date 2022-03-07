/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) 2021-2022 Missing Link Electronics, Inc.
 * Copyright(c) 2019 The Regents of the University of California
 */

#include "rte_eth_mqnic.h"

int mqnic_create_cq_ring(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc, unsigned int socket_id, struct rte_mempool *mp, bool is_tx)
{
    struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
    struct mqnic_hw *hw = MQNIC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
    struct mqnic_cq_ring *ring;
    struct rte_memzone *rz;
    int ret;

    PMD_INIT_FUNC_TRACE();

    ring = rte_zmalloc(NULL, sizeof(struct mqnic_cq_ring), RTE_CACHE_LINE_SIZE);
    if (!ring)
    {
        return -ENOMEM;
    }

    ring->size = rte_align32pow2(nb_desc);
    ring->size_mask = ring->size-1;
    ring->stride = rte_align32pow2(MQNIC_CPL_SIZE);

    ring->buf_size = ring->size*ring->stride;

    if(is_tx){
        rz = rte_eth_dma_zone_reserve(dev, "TX Completion Queue", queue_idx, ring->buf_size, 0x1000, socket_id);
    } else {
        rz = rte_eth_dma_zone_reserve(dev, "RX Completion Queue", queue_idx, ring->buf_size, 0x1000, socket_id);
    }
    if (rz == NULL)
    {
        PMD_INIT_LOG(NOTICE,"Initialization of the commpletion queue failed");
        ret = -ENOMEM;
        goto fail_ring;
    }

    ring->ring_phys_addr = (uint64_t) rz->iova;
    ring->buf = (uint8_t *) rz->addr;

    ring->head_ptr = 0;
    ring->tail_ptr = 0;
    ring->dev = dev;
    if(is_tx){
        ring->hw_addr = priv->hw_addr+priv->tx_cpl_queue_offset+queue_idx*MQNIC_CPL_QUEUE_STRIDE;
    }else {
        ring->hw_addr = priv->hw_addr+priv->rx_cpl_queue_offset+queue_idx*MQNIC_CPL_QUEUE_STRIDE;
    }
    ring->hw_ptr_mask = 0xffff;
    ring->hw_head_ptr = ring->hw_addr+MQNIC_CPL_QUEUE_HEAD_PTR_REG;
    ring->hw_tail_ptr = ring->hw_addr+MQNIC_CPL_QUEUE_TAIL_PTR_REG;

    // deactivate queue
    rte_write32(0, ring->hw_addr+MQNIC_CPL_QUEUE_ACTIVE_LOG_SIZE_REG);
    // set base address
    rte_write32(ring->ring_phys_addr, ring->hw_addr+MQNIC_CPL_QUEUE_BASE_ADDR_REG+0);
    rte_write32(ring->ring_phys_addr >> 32, ring->hw_addr+MQNIC_CPL_QUEUE_BASE_ADDR_REG+4);
    // set interrupt index
    rte_write32(queue_idx, ring->hw_addr+MQNIC_CPL_QUEUE_INTERRUPT_INDEX_REG);
    // set pointers
    rte_write32(ring->head_ptr & ring->hw_ptr_mask, ring->hw_addr+MQNIC_CPL_QUEUE_HEAD_PTR_REG);
    rte_write32(ring->tail_ptr & ring->hw_ptr_mask, ring->hw_addr+MQNIC_CPL_QUEUE_TAIL_PTR_REG);
    // set size
    rte_write32(rte_log2_u32(ring->size), ring->hw_addr+MQNIC_CPL_QUEUE_ACTIVE_LOG_SIZE_REG);

    if(is_tx) {
        priv->tx_cpl_ring[queue_idx] = ring;
    }else {
        priv->rx_cpl_ring[queue_idx] = ring;
    }
    return 0;

fail_ring:
    rte_free(ring);
    return ret;
}

void mqnic_destroy_cq_ring(struct rte_eth_dev *dev, struct mqnic_cq_ring **ring_ptr, bool is_tx)
{
    struct mqnic_cq_ring *ring = *ring_ptr;
    *ring_ptr = NULL;

    mqnic_deactivate_cq_ring(dev, ring);

    if(is_tx){
        rte_eth_dma_zone_free(dev, "TX Completion Queue", 0);
    } else {
        rte_eth_dma_zone_free(dev, "RX Completion Queue", 0);
    }
    rte_free(ring);
}

int mqnic_activate_cq_ring(struct rte_eth_dev *dev, struct mqnic_cq_ring *ring, int eq_index)
{
    ring->eq_index = eq_index;

    // deactivate queue
    rte_write32(0, ring->hw_addr+MQNIC_CPL_QUEUE_ACTIVE_LOG_SIZE_REG);
    // set base address
    rte_write32(ring->ring_phys_addr, ring->hw_addr+MQNIC_CPL_QUEUE_BASE_ADDR_REG+0);
    rte_write32(ring->ring_phys_addr >> 32, ring->hw_addr+MQNIC_CPL_QUEUE_BASE_ADDR_REG+4);
    // set interrupt index
    rte_write32(eq_index, ring->hw_addr+MQNIC_CPL_QUEUE_INTERRUPT_INDEX_REG);
    // set pointers
    rte_write32(ring->head_ptr & ring->hw_ptr_mask, ring->hw_addr+MQNIC_CPL_QUEUE_HEAD_PTR_REG);
    rte_write32(ring->tail_ptr & ring->hw_ptr_mask, ring->hw_addr+MQNIC_CPL_QUEUE_TAIL_PTR_REG);
    // set size and activate queue
    rte_write32(rte_log2_u32(ring->size) | MQNIC_CPL_QUEUE_ACTIVE_MASK, ring->hw_addr+MQNIC_CPL_QUEUE_ACTIVE_LOG_SIZE_REG);

    return 0;
}

void mqnic_deactivate_cq_ring(struct rte_eth_dev *dev, struct mqnic_cq_ring *ring)
{
    // deactivate queue
    rte_write32(rte_log2_u32(ring->size), ring->hw_addr+MQNIC_CPL_QUEUE_ACTIVE_LOG_SIZE_REG);
    // disarm queue
    rte_write32(ring->eq_index, ring->hw_addr+MQNIC_CPL_QUEUE_INTERRUPT_INDEX_REG);
}

bool mqnic_is_cq_ring_empty(const struct mqnic_cq_ring *ring)
{
    return ring->head_ptr == ring->tail_ptr;
}

bool mqnic_is_cq_ring_full(const struct mqnic_cq_ring *ring)
{
    return ring->head_ptr - ring->tail_ptr >= ring->size;
}

void mqnic_cq_read_head_ptr(struct mqnic_cq_ring *ring)
{
    ring->head_ptr += (rte_read32(ring->hw_head_ptr) - ring->head_ptr) & ring->hw_ptr_mask;
}

void mqnic_cq_write_tail_ptr(struct mqnic_cq_ring *ring)
{
    rte_write32(ring->tail_ptr & ring->hw_ptr_mask, ring->hw_tail_ptr);
}

void mqnic_arm_cq(struct mqnic_cq_ring *ring)
{
    rte_write32(ring->eq_index | MQNIC_CPL_QUEUE_ARM_MASK, ring->hw_addr+MQNIC_CPL_QUEUE_INTERRUPT_INDEX_REG);
}
