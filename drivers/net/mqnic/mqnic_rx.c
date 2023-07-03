/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) 2021-2023 Missing Link Electronics, Inc.
 * Copyright(c) 2019 The Regents of the University of California
 */

#include "rte_eth_mqnic.h"

int
mqnic_create_rx_ring(struct mqnic_if *interface,
			struct mqnic_ring **ring_ptr_if,
			struct mqnic_ring **ring_ptr_priv,
			uint16_t queue_idx,
			uint8_t *hw_addr,
			__rte_unused const struct rte_eth_rxconf *rx_conf,
			struct rte_mempool *mp)
{

	struct mqnic_ring *rxq;
	PMD_INIT_FUNC_TRACE();

	rxq = rte_zmalloc(NULL, sizeof(struct mqnic_ring), RTE_CACHE_LINE_SIZE);

	if (rxq == NULL) {
		PMD_INIT_LOG(ERR, "Allocation rx queue failed");
		return -ENOMEM;
	}
	rxq->mp = mp;

	*ring_ptr_if = rxq;
	*ring_ptr_priv = rxq;


	rxq->dev = interface->dev;
	rxq->interface = interface;
	rxq->hw_ptr_mask = 0xffff;
	rxq->cpl_index = queue_idx;
	rxq->index = queue_idx;


	rxq->head_ptr = 0;
	rxq->tail_ptr = 0;
	rxq->clean_tail_ptr = 0;
	rxq->active = 0;
	rxq->hw_addr = hw_addr;
	rxq->hw_head_ptr = hw_addr + MQNIC_QUEUE_HEAD_PTR_REG;
	rxq->hw_tail_ptr = hw_addr + MQNIC_QUEUE_TAIL_PTR_REG;

	// Make RX Queue for DPDK available
	interface->dev->data->rx_queues[queue_idx] = rxq;

	return 0;
}

int
mqnic_alloc_rx_ring(struct rte_eth_dev *dev, struct mqnic_ring *rxq, int size, int stride)
{
	const struct rte_memzone *rz;
	rxq->size = rte_align32pow2(size);
	rxq->size_mask = rxq->size - 1;
	rxq->stride = rte_align32pow2(stride);

	rxq->desc_block_size = rxq->stride / MQNIC_DESC_SIZE;
	rxq->log_desc_block_size = rxq->desc_block_size < 2 ? 0 : rte_log2_u32(rxq->desc_block_size - 1) + 1;
	rxq->desc_block_size = 1 << rxq->log_desc_block_size;

	rxq->buf_size = rxq->size * rxq->stride;
	rz = rte_eth_dma_zone_reserve(dev, "rx_ring", rxq->index, rxq->buf_size, PAGE_SIZE, 0);

	if (rz == NULL) {
		PMD_INIT_LOG(ERR, "DMA Failed");
		rte_free(rxq);
		return -ENOMEM;
	}

	rxq->rx_info = rte_zmalloc(NULL, sizeof(struct mqnic_rx_info) * rxq->size, RTE_CACHE_LINE_SIZE);
	if (rxq->rx_info == NULL) {
		PMD_INIT_LOG(ERR, "RX Info Failed");
		rte_free(rxq);
		return -ENOMEM;
	}

	rxq->ring_phys_addr = rz->iova;
	rxq->buf = rz->addr;

	rxq->head_ptr = 0;
	rxq->tail_ptr = 0;
	rxq->clean_tail_ptr = 0;

	// deactivate queue
	rte_write32(0, rxq->hw_addr + MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
	// set base address
	rte_write32(rxq->ring_phys_addr, rxq->hw_addr + MQNIC_QUEUE_BASE_ADDR_REG + 0);
	rte_write32(rxq->ring_phys_addr >> 32, rxq->hw_addr + MQNIC_QUEUE_BASE_ADDR_REG + 4);
	// set completion queue index
	rte_write32(rxq->index, rxq->hw_addr + MQNIC_QUEUE_CPL_QUEUE_INDEX_REG);
	// set pointers
	rte_write32(rxq->head_ptr & rxq->hw_ptr_mask, rxq->hw_addr + MQNIC_QUEUE_HEAD_PTR_REG);
	rte_write32(rxq->tail_ptr & rxq->hw_ptr_mask, rxq->hw_addr + MQNIC_QUEUE_TAIL_PTR_REG);
	// set size
	rte_write32(rte_log2_u32(rxq->size) | (rxq->log_desc_block_size << 8),
				rxq->hw_addr + MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
	return 0;
}

void
mqnic_destroy_rx_ring(struct rte_eth_dev *dev, struct mqnic_ring *ring)
{
	PMD_INIT_FUNC_TRACE();
	if(ring != NULL){
		mqnic_deactivate_rx_ring(ring);
		mqnic_free_rx_buf(ring);

		rte_eth_dma_zone_free(dev, "rx_ring", ring->index);
		rte_free(ring);
	}
}

int
mqnic_activate_rx_ring(struct rte_eth_dev *dev, struct mqnic_ring *ring, int cpl_index)
{
	rte_write32(0, ring->hw_addr + MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
	// set base address
	rte_write32(ring->ring_phys_addr, ring->hw_addr + MQNIC_QUEUE_BASE_ADDR_REG + 0);
	rte_write32(ring->ring_phys_addr >> 32, ring->hw_addr + MQNIC_QUEUE_BASE_ADDR_REG + 4);
	// set completion queue index
	rte_write32(cpl_index, ring->hw_addr + MQNIC_QUEUE_CPL_QUEUE_INDEX_REG);
	// set pointers
	rte_write32(ring->head_ptr & ring->hw_ptr_mask, ring->hw_head_ptr);
	rte_write32(ring->tail_ptr & ring->hw_ptr_mask, ring->hw_tail_ptr);
	// set size and activate queue
	rte_write32(rte_log2_u32(ring->size) | (ring->log_desc_block_size << 8) | MQNIC_QUEUE_ACTIVE_MASK,
				ring->hw_addr + MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);

	mqnic_refill_rx_buffers(dev, ring);

	return 0;
}

void
mqnic_deactivate_rx_ring(struct mqnic_ring *ring)
{
	// deactivate queue
	rte_write32(rte_log2_u32(ring->size) | (ring->log_desc_block_size << 8),
				ring->hw_addr + MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
}

bool
mqnic_is_rx_ring_empty(const struct mqnic_ring *ring)
{
	return ring->head_ptr == ring->clean_tail_ptr;
}

bool
mqnic_is_rx_ring_full(const struct mqnic_ring *ring)
{
	return ring->head_ptr - ring->clean_tail_ptr >= ring->size;
}

void
mqnic_rx_read_tail_ptr(struct mqnic_ring *ring)
{
	ring->tail_ptr += (rte_read32(ring->hw_tail_ptr) - ring->tail_ptr) & ring->hw_ptr_mask;
}

void
mqnic_rx_write_head_ptr(struct mqnic_ring *ring)
{
	rte_write32(ring->head_ptr & ring->hw_ptr_mask, ring->hw_head_ptr);
}

void
mqnic_free_rx_desc(struct mqnic_ring *ring, int index)
{
	struct mqnic_rx_info *rx_info = &ring->rx_info[index];
	struct rte_mbuf *page = rx_info->page;
	PMD_INIT_FUNC_TRACE();

	rte_pktmbuf_free(page);
	rx_info->dma_addr = 0;
	rx_info->len =  0;
}

int
mqnic_free_rx_buf(struct mqnic_ring *ring)
{
	uint32_t index;
	int cnt = 0;

	while (!mqnic_is_rx_ring_empty(ring)) {
		index = ring->clean_tail_ptr & ring->size_mask;
		mqnic_free_rx_desc(ring, index);
		ring->clean_tail_ptr++;
		cnt++;
	}

	ring->head_ptr = 0;
	ring->tail_ptr = 0;
	ring->clean_tail_ptr = 0;

	return cnt;
}

int
mqnic_prepare_rx_desc(__rte_unused struct rte_eth_dev *dev, struct mqnic_ring *ring, int index)
{
	struct mqnic_rx_info *rx_info = &ring->rx_info[index];
	struct mqnic_desc *rx_desc = (struct mqnic_desc *)(ring->buf + index * ring->stride);
	struct rte_mbuf *page;
	uint32_t page_order = ring->page_order;
	uint32_t len = PAGE_SIZE << page_order;
	uint64_t dma_addr;

	page = rte_pktmbuf_alloc(ring->mp);
	if (unlikely(!page)) {
		PMD_INIT_LOG(ERR, "Failed to allocate memory");
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

void
mqnic_refill_rx_buffers(struct rte_eth_dev *dev, struct mqnic_ring *ring)
{
	uint32_t missing = ring->size - (ring->head_ptr - ring->clean_tail_ptr);

	if (missing < 8)
		return;

	for (; missing-- > 0;) {
		if (mqnic_prepare_rx_desc(dev, ring, ring->head_ptr & ring->size_mask))
			break;
		ring->head_ptr++;
	}

	// enqueue on NIC
	rte_wmb();
	mqnic_rx_write_head_ptr(ring);
}

int
mqnic_process_rx_cq(struct mqnic_ring *rx_ring, int napi_budget, struct rte_mbuf **bufs)
{
	PMD_INIT_FUNC_TRACE();
	struct rte_eth_dev *dev = rx_ring->dev;
	struct mqnic_priv *priv = MQNIC_DEV_PRIVATE(dev->data->dev_private);
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

	if (unlikely(!priv || !priv->port_up)) {
		PMD_INIT_LOG(NOTICE, "Port not up or private data is NULL");
		return done;
	}

	// process completion queue
	// read head pointer from NIC
	mqnic_cq_read_head_ptr(cq_ring);

	cq_tail_ptr = cq_ring->tail_ptr;
	cq_index = cq_tail_ptr & cq_ring->size_mask;

	rte_mb();// is a barrier here necessary?  If so, what kind?

	while (cq_ring->head_ptr != cq_tail_ptr && done < budget) {
		cpl = (struct mqnic_cpl *)(cq_ring->buf + cq_index * cq_ring->stride);
		ring_index = rte_le_to_cpu_16(cpl->index) & rx_ring->size_mask;
		rx_info = &rx_ring->rx_info[ring_index];
		page = rx_info->page;

		if (unlikely(!page)) {
			PMD_INIT_LOG(ERR, "mqnic_process_rx_cq ring %d null page at index %d", cq_ring->ring_index,
					ring_index);
			break;
		}

		rte_prefetch1((char *)page->buf_addr);

		page->nb_segs = 1;
		page->pkt_len = RTE_MIN(rte_le_to_cpu_32(cpl->len), rx_info->len);
		page->data_len = RTE_MIN(rte_le_to_cpu_32(cpl->len), rx_info->len);
		page->port = 0;

		bufs[done] = page;
		rx_info->page = NULL;
		done++;
		rx_ring->packets++;
		rx_ring->bytes += page->pkt_len;

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

	while (ring_clean_tail_ptr != rx_ring->tail_ptr) {
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
