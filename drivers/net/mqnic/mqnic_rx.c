/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) 2021-2022 Missing Link Electronics, Inc.
 * Copyright(c) 2019 The Regents of the University of California
 */

#include "rte_eth_mqnic.h"

int mqnic_create_rx_ring(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc, unsigned int socket_id, const struct rte_eth_rxconf *rx_conf, struct rte_mempool *mp)
{
    struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
    struct mqnic_hw *hw = MQNIC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
    struct mqnic_ring *rxq;
    const struct rte_memzone *rz;
    int ret = -42;
    PMD_INIT_FUNC_TRACE();

    rxq = rte_zmalloc_socket("ethdev RX queue", sizeof(struct mqnic_ring), RTE_CACHE_LINE_SIZE, socket_id);

	if (rxq == NULL){
        PMD_INIT_LOG(NOTICE, "Allocation rx queue failed");
		return -ENOMEM;
    }
	rxq->mp = mp;

    rxq->size = rte_align32pow2(nb_desc);
    rxq->size_mask = rxq->size-1;
    rxq->stride = rte_align32pow2(MQNIC_DESC_SIZE);

    rxq->desc_block_size = rxq->stride/MQNIC_DESC_SIZE;
    rxq->log_desc_block_size = rxq->desc_block_size < 2 ? 0 : rte_log2_u32(rxq->desc_block_size-1)+1;
    rxq->desc_block_size = 1 << rxq->log_desc_block_size;

    rxq->buf_size = rxq->size*rxq->stride;
	rz = rte_eth_dma_zone_reserve(dev, "rx_ring", queue_idx, rxq->buf_size, 0x1000, socket_id);

	if (rz == NULL) {
		PMD_INIT_LOG(NOTICE, "DMA Failed");
        goto fail_ring;
	}

    rxq->dev = dev;
	rxq->ring_phys_addr = rz->iova;
    rxq->buf = rz->addr;
	rxq->hw_ptr_mask = 0xffff;
    rxq->cpl_index = queue_idx;

    rxq->rx_info = rte_zmalloc_socket(NULL, sizeof(struct mqnic_rx_info)*rxq->size, RTE_CACHE_LINE_SIZE, socket_id);
    if (rxq->rx_info == NULL) {
		PMD_INIT_LOG(NOTICE, "RX Info Failed");
        goto fail_ring;
	}
    rxq->head_ptr = 0;
    rxq->tail_ptr = 0;
    rxq->clean_tail_ptr = 0;
    rxq->hw_addr = priv->hw_addr+priv->rx_queue_offset+queue_idx*MQNIC_QUEUE_STRIDE;
    rxq->hw_head_ptr = rxq->hw_addr+MQNIC_QUEUE_HEAD_PTR_REG;
    rxq->hw_tail_ptr = rxq->hw_addr+MQNIC_QUEUE_TAIL_PTR_REG;

	// deactivate queue
    rte_write32(0, rxq->hw_addr+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
    // set base address
    rte_write32(rxq->ring_phys_addr, rxq->hw_addr+MQNIC_QUEUE_BASE_ADDR_REG+0);
    rte_write32(rxq->ring_phys_addr >> 32, rxq->hw_addr+MQNIC_QUEUE_BASE_ADDR_REG+4);
    // set completion queue index
    rte_write32(queue_idx, rxq->hw_addr+MQNIC_QUEUE_CPL_QUEUE_INDEX_REG);
    // set pointers
    rte_write32(rxq->head_ptr & rxq->hw_ptr_mask, rxq->hw_addr+MQNIC_QUEUE_HEAD_PTR_REG);
    rte_write32(rxq->tail_ptr & rxq->hw_ptr_mask, rxq->hw_addr+MQNIC_QUEUE_TAIL_PTR_REG);
    // set size
    rte_write32(rte_log2_u32(rxq->size) | (rxq->log_desc_block_size << 8), rxq->hw_addr+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
    priv->rx_ring[queue_idx] = rxq;
    dev->data->rx_queues[queue_idx] = rxq;
    return 0;

fail_ring:
    rte_free(rxq);
    return ret;
}

void mqnic_destroy_rx_ring(struct rte_eth_dev *dev, struct mqnic_ring **ring_ptr)
{
    struct mqnic_ring *ring = *ring_ptr;
    *ring_ptr = NULL;

    mqnic_deactivate_rx_ring(dev, ring);

    mqnic_free_rx_buf(dev, ring);

    rte_eth_dma_zone_free(dev, "rx_ring", 0);
    rte_free(ring->rx_info);
    ring->rx_info = NULL;
    rte_free(ring);
}

int mqnic_activate_rx_ring(struct rte_eth_dev *dev, struct mqnic_ring *ring, int cpl_index)
{
    rte_write32(0, ring->hw_addr+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
    // set base address
    rte_write32(ring->ring_phys_addr, ring->hw_addr+MQNIC_QUEUE_BASE_ADDR_REG+0);
    rte_write32(ring->ring_phys_addr >> 32, ring->hw_addr+MQNIC_QUEUE_BASE_ADDR_REG+4);
    // set completion queue index
    rte_write32(cpl_index, ring->hw_addr+MQNIC_QUEUE_CPL_QUEUE_INDEX_REG);
    // set pointers
    rte_write32(ring->head_ptr & ring->hw_ptr_mask, ring->hw_head_ptr);
    rte_write32(ring->tail_ptr & ring->hw_ptr_mask, ring->hw_tail_ptr);
    // set size and activate queue
    rte_write32(rte_log2_u32(ring->size) | (ring->log_desc_block_size << 8) | MQNIC_QUEUE_ACTIVE_MASK, ring->hw_addr+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);

    mqnic_refill_rx_buffers(dev, ring);

    return 0;
}

void mqnic_deactivate_rx_ring(struct rte_eth_dev *dev, struct mqnic_ring *ring)
{
    // deactivate queue
    rte_write32(rte_log2_u32(ring->size) | (ring->log_desc_block_size << 8), ring->hw_addr+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
}

bool mqnic_is_rx_ring_empty(const struct mqnic_ring *ring)
{
    return ring->head_ptr == ring->clean_tail_ptr;
}

bool mqnic_is_rx_ring_full(const struct mqnic_ring *ring)
{
    return ring->head_ptr - ring->clean_tail_ptr >= ring->size;
}

void mqnic_rx_read_tail_ptr(struct mqnic_ring *ring)
{
    ring->tail_ptr += (rte_read32(ring->hw_tail_ptr) - ring->tail_ptr) & ring->hw_ptr_mask;
}

void mqnic_rx_write_head_ptr(struct mqnic_ring *ring)
{
    rte_write32(ring->head_ptr & ring->hw_ptr_mask, ring->hw_head_ptr);
}

void mqnic_free_rx_desc(struct rte_eth_dev *dev, struct mqnic_ring *ring, int index)
{
    struct mqnic_rx_info *rx_info = &ring->rx_info[index];
    struct rte_mbuf *page = rx_info->page;

    rte_pktmbuf_free(page);
    rx_info->dma_addr = 0;
    rx_info->page = NULL;
}

int mqnic_free_rx_buf(struct rte_eth_dev *dev, struct mqnic_ring *ring)
{
    uint32_t index;
    int cnt = 0;

    while (!mqnic_is_rx_ring_empty(ring))
    {
        index = ring->clean_tail_ptr & ring->size_mask;
        mqnic_free_rx_desc(dev, ring, index);
        ring->clean_tail_ptr++;
        cnt++;
    }

    ring->head_ptr = 0;
    ring->tail_ptr = 0;
    ring->clean_tail_ptr = 0;

    return cnt;
}

int mqnic_prepare_rx_desc(struct rte_eth_dev *dev, struct mqnic_ring *ring, int index)
{
    struct mqnic_rx_info *rx_info = &ring->rx_info[index];
    struct mqnic_desc *rx_desc = (struct mqnic_desc *)(ring->buf + index*ring->stride);
    struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
    struct rte_mbuf *page;
    uint32_t page_order = ring->page_order;
    uint32_t len = PAGE_SIZE << page_order;
    uint64_t dma_addr;

    page = rte_pktmbuf_alloc(ring->mp);
    if (unlikely(!page))
    {
        PMD_INIT_LOG(NOTICE, "mqnic_prepare_rx_desc failed to allocate memory on port %d", priv->port);
        return -1;
    }

    // map page
    page->data_off = RTE_PKTMBUF_HEADROOM;
    dma_addr = rte_mbuf_data_iova_default(page);

    // write descriptor
    rx_desc->len = len;
    rx_desc->addr = rte_cpu_to_le_64(dma_addr);

    // update rx_info
    rx_info->page = page;
    rx_info->page_order = page_order;
    rx_info->page_offset = 0;
    rx_info->dma_addr = dma_addr;
    rx_info->len = len;

    return 0;
}

void mqnic_refill_rx_buffers(struct rte_eth_dev *dev, struct mqnic_ring *ring)
{
    uint32_t missing = ring->size - (ring->head_ptr - ring->clean_tail_ptr);

    if (missing < 8)
        return;

    for ( ; missing-- > 0; )
    {
        if (mqnic_prepare_rx_desc(dev, ring, ring->head_ptr & ring->size_mask))
            break;
        ring->head_ptr++;
    }

    // enqueue on NIC
    rte_wmb();
    mqnic_rx_write_head_ptr(ring);
}

int mqnic_process_rx_cq(struct mqnic_ring *rx_ring, int napi_budget, struct rte_mbuf **bufs)
{
    struct rte_eth_dev *dev = rx_ring->dev;
    struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
    struct mqnic_cq_ring *cq_ring = priv->rx_cpl_ring[rx_ring->cpl_index];
    struct mqnic_rx_info *rx_info;
    struct mqnic_cpl *cpl;
    struct rte_mbuf *page;
    uint32_t cq_index;
    uint32_t cq_tail_ptr;
    uint32_t ring_index;
    uint32_t ring_clean_tail_ptr;
    int done = 0;
    int budget = napi_budget;

    if (unlikely(!priv->port_up))
    {
        return done;
    }

    // process completion queue
    // read head pointer from NIC
    mqnic_cq_read_head_ptr(cq_ring);

    cq_tail_ptr = cq_ring->tail_ptr;
    cq_index = cq_tail_ptr & cq_ring->size_mask;

    rte_mb(); // is a barrier here necessary?  If so, what kind?

    while (cq_ring->head_ptr != cq_tail_ptr && done < budget)
    {
        cpl = (struct mqnic_cpl *)(cq_ring->buf + cq_index*cq_ring->stride);
        ring_index = rte_le_to_cpu_16(cpl->index) & rx_ring->size_mask;
        rx_info = &rx_ring->rx_info[ring_index];
        page = rx_info->page;

        if (unlikely(!page))
        {
            PMD_INIT_LOG(NOTICE, "mqnic_process_rx_cq ring %d null page at index %d", cq_ring->ring_index, ring_index);
            break;
        }

        rte_prefetch1((char *)page->buf_addr);

        page->nb_segs = 1;
        page->pkt_len =  RTE_MIN(rte_le_to_cpu_32(cpl->len), rx_info->len);
        page->data_len = RTE_MIN(rte_le_to_cpu_32(cpl->len), rx_info->len);
        page->port = 0;

        bufs[done] = page;
        rx_info->page = NULL;
        done++;
        rx_ring->packets++;

        cq_tail_ptr++;
        cq_index = cq_tail_ptr & cq_ring->size_mask;
    }

    // update CQ tail
    cq_ring->tail_ptr = cq_tail_ptr;
    mqnic_cq_write_tail_ptr(cq_ring);

    // process ring
    // read tail pointer from NIC
    mqnic_rx_read_tail_ptr(rx_ring);

    ring_clean_tail_ptr = rx_ring->clean_tail_ptr;
    ring_index = ring_clean_tail_ptr & rx_ring->size_mask;

    while (ring_clean_tail_ptr != rx_ring->tail_ptr)
    {
        rx_info = &rx_ring->rx_info[ring_index];

        if (rx_info->page)
            break;

        ring_clean_tail_ptr++;
        ring_index = ring_clean_tail_ptr & rx_ring->size_mask;
    }

    // update ring tail
    rx_ring->clean_tail_ptr = ring_clean_tail_ptr;

    // replenish buffers
    mqnic_refill_rx_buffers(dev, rx_ring);

    return done;
}

