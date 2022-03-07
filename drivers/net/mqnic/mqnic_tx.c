/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) 2021-2022 Missing Link Electronics, Inc.
 * Copyright(c) 2019 The Regents of the University of California
 */

#include "rte_eth_mqnic.h"

int mqnic_create_tx_ring(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc, unsigned int socket_id, const struct rte_eth_txconf *tx_conf)
{
    struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
    struct mqnic_ring *txq;
    const struct rte_memzone *rz;
    int ret = -42;
    PMD_INIT_FUNC_TRACE();


	uint32_t desc_block_size;
    desc_block_size = priv->max_desc_block_size < 4 ? priv->max_desc_block_size : 4;

    txq = rte_zmalloc_socket("ethdev TX queue", sizeof(struct mqnic_ring),
				 RTE_CACHE_LINE_SIZE, socket_id);

	if (txq == NULL)
		return -ENOMEM;

    txq->size = rte_align32pow2(nb_desc * desc_block_size);
    txq->full_size = txq->size >> 1;
    txq->size_mask = txq->size-1;
    txq->stride = rte_align32pow2(MQNIC_DESC_SIZE);

    txq->desc_block_size = txq->stride/MQNIC_DESC_SIZE;
    txq->log_desc_block_size = txq->desc_block_size < 2 ? 0 : rte_log2_u32(txq->desc_block_size-1)+1;
    txq->desc_block_size = 1 << txq->log_desc_block_size;

    txq->buf_size = txq->size*txq->stride;
	rz = rte_eth_dma_zone_reserve(dev, "tx_ring", queue_idx,
					txq->buf_size, 0x1000, socket_id);

	if (rz == NULL) {
		PMD_INIT_LOG(NOTICE, "DMA Failed");
        goto fail_ring;
		return -ENOMEM;
	}

    txq->dev = dev;
	txq->ring_phys_addr = rz->iova;
    txq->buf = rz->addr;
	txq->hw_ptr_mask = 0xffff;

    txq->tx_info = rte_zmalloc_socket(NULL, sizeof(struct mqnic_tx_info)*txq->size, RTE_CACHE_LINE_SIZE, socket_id);
    if (txq->tx_info == NULL) {
		PMD_INIT_LOG(NOTICE, "TX Info Failed");
        goto fail_ring;
	}

    txq->head_ptr = 0;
    txq->tail_ptr = 0;
    txq->clean_tail_ptr = 0;
    txq->hw_addr = priv->csr_hw_addr+priv->tx_queue_offset+queue_idx*MQNIC_QUEUE_STRIDE;
    txq->hw_head_ptr = txq->hw_addr+MQNIC_QUEUE_HEAD_PTR_REG;
    txq->hw_tail_ptr = txq->hw_addr+MQNIC_QUEUE_TAIL_PTR_REG;

	// deactivate queue
    rte_write32(0, txq->hw_addr+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
    // set base address
    rte_write32(txq->ring_phys_addr, txq->hw_addr+MQNIC_QUEUE_BASE_ADDR_REG+0);
    rte_write32(txq->ring_phys_addr >> 32, txq->hw_addr+MQNIC_QUEUE_BASE_ADDR_REG+4);
    // set completion queue index
    rte_write32(0, txq->hw_addr+MQNIC_QUEUE_CPL_QUEUE_INDEX_REG);
    // set pointers
    rte_write32(txq->head_ptr & txq->hw_ptr_mask, txq->hw_addr+MQNIC_QUEUE_HEAD_PTR_REG);
    rte_write32(txq->tail_ptr & txq->hw_ptr_mask, txq->hw_addr+MQNIC_QUEUE_TAIL_PTR_REG);
    // set size
    rte_write32(rte_log2_u32(txq->size) | (txq->log_desc_block_size << 8), txq->hw_addr+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
    priv->tx_ring[queue_idx] = txq;
    dev->data->tx_queues[queue_idx] = txq;
    return 0;

fail_ring:
    rte_free(txq);
    return ret;
}

void mqnic_destroy_tx_ring(struct rte_eth_dev *dev, struct mqnic_ring **ring_ptr)
{
    struct mqnic_ring *ring = *ring_ptr;
    *ring_ptr = NULL;

    mqnic_deactivate_tx_ring(dev, ring);

    mqnic_free_tx_buf(dev, ring);

    rte_eth_dma_zone_free(dev, "tx_ring", 0);
    rte_free(ring->tx_info);
    ring->tx_info = NULL;
    rte_free(ring);
}

int mqnic_activate_tx_ring(struct rte_eth_dev *dev, struct mqnic_ring *ring, int cpl_index)
{
    // deactivate queue
    rte_write32(0, ring->hw_addr+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
    // set base address
    rte_write32(ring->ring_phys_addr, ring->hw_addr+MQNIC_QUEUE_BASE_ADDR_REG+0);
    rte_write32(ring->ring_phys_addr >> 32, ring->hw_addr+MQNIC_QUEUE_BASE_ADDR_REG+4);
    // set completion queue index
    rte_write32(cpl_index, ring->hw_addr+MQNIC_QUEUE_CPL_QUEUE_INDEX_REG);
    // set pointers
    rte_write32(ring->head_ptr & ring->hw_ptr_mask, ring->hw_addr+MQNIC_QUEUE_HEAD_PTR_REG);
    rte_write32(ring->tail_ptr & ring->hw_ptr_mask, ring->hw_addr+MQNIC_QUEUE_TAIL_PTR_REG);
    // set size and activate queue
    rte_write32(rte_log2_u32(ring->size) | (ring->log_desc_block_size << 8) | MQNIC_QUEUE_ACTIVE_MASK, ring->hw_addr+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);

    return 0;
}

void mqnic_deactivate_tx_ring(struct rte_eth_dev *dev, struct mqnic_ring *ring)
{
    // deactivate queue
    rte_write32(rte_log2_u32(ring->size) | (ring->log_desc_block_size << 8), ring->hw_addr+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG);
}

bool mqnic_is_tx_ring_empty(const struct mqnic_ring *ring)
{
    return ring->head_ptr == ring->clean_tail_ptr;
}

bool mqnic_is_tx_ring_full(const struct mqnic_ring *ring)
{
    return ring->head_ptr - ring->clean_tail_ptr >= ring->full_size;
}

void mqnic_tx_read_tail_ptr(struct mqnic_ring *ring)
{
    ring->tail_ptr += (rte_read32(ring->hw_tail_ptr) - ring->tail_ptr) & ring->hw_ptr_mask;
}

void mqnic_tx_write_head_ptr(struct mqnic_ring *ring)
{
    rte_write32(ring->head_ptr & ring->hw_ptr_mask, ring->hw_head_ptr);
}

void mqnic_free_tx_desc(struct rte_eth_dev *dev, struct mqnic_ring *ring, int index, int napi_budget)
{
    struct mqnic_tx_info *tx_info = &ring->tx_info[index];
    struct rte_mbuf *page = tx_info->page;
    uint32_t i;

    tx_info->page = rte_pktmbuf_prefree_seg(tx_info->page);
    tx_info->dma_addr = 0;
    tx_info->len = 0;
}

int mqnic_free_tx_buf(struct rte_eth_dev *dev, struct mqnic_ring *ring)
{
    uint32_t index;
    int cnt = 0;

    while (!mqnic_is_tx_ring_empty(ring))
    {
        index = ring->clean_tail_ptr & ring->size_mask;
        mqnic_free_tx_desc(dev, ring, index, 0);
        ring->clean_tail_ptr++;
        cnt++;
    }

    ring->head_ptr = 0;
    ring->tail_ptr = 0;
    ring->clean_tail_ptr = 0;

    return cnt;
}

int mqnic_process_tx_cq(struct mqnic_ring *tx_ring, struct rte_mbuf **tx_pkts, uint16_t nb_packets)
{
    PMD_INIT_FUNC_TRACE();
    struct rte_eth_dev *dev = tx_ring->dev;
    struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
    struct mqnic_cq_ring *cq_ring = priv->tx_cpl_ring[tx_ring->cpl_index];
    struct mqnic_tx_info *tx_info;
    struct mqnic_cpl *cpl;
    uint32_t cq_index;
    uint32_t cq_tail_ptr;
    uint32_t ring_index;
    uint32_t ring_clean_tail_ptr;
    uint32_t packets = 0;
    uint32_t bytes = 0;
    int done = 0;
    int budget = nb_packets;

    if (unlikely(!priv->port_up))
    {
        PMD_INIT_LOG(NOTICE, "Port is not up");
        return done;
    }

    // process completion queue
    // read head pointer from NIC
    mqnic_cq_read_head_ptr(cq_ring);

    cq_tail_ptr = cq_ring->tail_ptr;
    cq_index = cq_tail_ptr & cq_ring->size_mask;

    while (cq_ring->head_ptr != cq_tail_ptr && done < budget)
    {
        cpl = (struct mqnic_cpl *)(cq_ring->buf + cq_index*cq_ring->stride);
        ring_index = rte_le_to_cpu_16(cpl->index) & tx_ring->size_mask;
        tx_info = &tx_ring->tx_info[ring_index];

        // free TX descriptor
        mqnic_free_tx_desc(dev, tx_ring, ring_index, nb_packets);

        packets++;
        bytes += rte_le_to_cpu_16(cpl->len);

        done++;

        cq_tail_ptr++;
        cq_index = cq_tail_ptr & cq_ring->size_mask;
    }

    // update CQ tail
    cq_ring->tail_ptr = cq_tail_ptr;
    mqnic_cq_write_tail_ptr(cq_ring);

    // process ring
    // read tail pointer from NIC
    mqnic_tx_read_tail_ptr(tx_ring);

    ring_clean_tail_ptr = tx_ring->clean_tail_ptr;
    ring_index = ring_clean_tail_ptr & tx_ring->size_mask;

    while (ring_clean_tail_ptr != tx_ring->tail_ptr)
    {
        tx_info = &tx_ring->tx_info[ring_index];

        if (tx_info->page)
            break;

        ring_clean_tail_ptr++;
        ring_index = ring_clean_tail_ptr & tx_ring->size_mask;
    }

    // update ring tail
    tx_ring->clean_tail_ptr = ring_clean_tail_ptr;
    return done;
}

static bool mqnic_map_skb(struct mqnic_ifhw *priv, struct mqnic_ring *ring, struct mqnic_tx_info *tx_info, struct mqnic_desc *tx_desc, struct rte_mbuf **mbuf)
{
    uint32_t i = 0;
    uint32_t len;
    uint64_t dma_addr;
    struct rte_mbuf *tx_pkt;

    // update tx_info
    tx_info->page = *mbuf;
    tx_info->frag_count = 0;
    tx_pkt = *mbuf;


    len = tx_pkt->pkt_len;
    dma_addr = rte_mbuf_data_iova_default(tx_pkt);

    // write descriptor
    tx_desc[i+1].len = rte_cpu_to_le_32(len);
    tx_desc[i+1].addr = rte_cpu_to_le_64(dma_addr);
    tx_desc[i+1].tx_csum_cmd = 0;

    // update tx_info
    tx_info->frag_count = i+1;
    tx_info->frags[i].len = len;
    tx_info->frags[i].dma_addr = dma_addr;

    tx_desc[1].len = 0;
    tx_desc[1].addr = 0;

    // write descriptor
    tx_desc[0].len = rte_cpu_to_le_32(len);
    tx_desc[0].addr = rte_cpu_to_le_64(dma_addr);

    return true;

map_error:
    PMD_INIT_LOG(NOTICE, "mqnic_map_skb DMA mapping failed");

    // update tx_info
    tx_info->page = NULL;
    tx_info->frag_count = 0;

    return false;
}

int mqnic_start_xmit(struct mqnic_ring *tx_ring, struct rte_mbuf **mbuf, int num_packets)
{
    PMD_INIT_FUNC_TRACE();
    struct rte_eth_dev *dev = tx_ring->dev;
    struct mqnic_ifhw *priv = MQNIC_DEV_PRIVATE_TO_IFHW(dev->data->dev_private);
    struct mqnic_ring *ring;
    struct mqnic_tx_info *tx_info;
    struct mqnic_desc *tx_desc;
    uint32_t ring_index;
    uint32_t index;
    bool stop_queue;
    int packets_send = 0;

    if (unlikely(!priv->port_up))
    {
        goto tx_drop_count;
    }

    ring_index = tx_ring->cpl_index;

    if (unlikely((ring_index >= priv->tx_queue_count)))
    {
        // queue mapping out of range
        goto tx_drop_count;
    }

    ring = priv->tx_ring[ring_index];
    index = ring->head_ptr & ring->size_mask;
    tx_desc = (struct mqnic_desc *)(ring->buf + index*ring->stride);
    tx_info = &ring->tx_info[index];

    // map skb
    if (!mqnic_map_skb(priv, ring, tx_info, tx_desc, mbuf))
    {
        // map failed
        PMD_INIT_LOG(NOTICE, "Dropped");
        goto tx_drop_count;
    }

    // count packet
    ring->packets++;
    ring->bytes += mbuf[0]->data_len;
    packets_send++;

    // enqueue
    ring->head_ptr++;

    stop_queue = mqnic_is_tx_ring_full(ring);
    if (unlikely(stop_queue))
    {
        PMD_INIT_LOG(NOTICE, "mqnic_start_xmit TX ring %d full on port %d", ring_index, priv->port);
    }

    rte_wmb();
    mqnic_tx_write_head_ptr(ring);

    return packets_send;

tx_drop_count:
    ring->dropped_packets++;
    return 0;
}

