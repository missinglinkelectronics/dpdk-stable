/* SPDX-License-Identifier: BSD-2-Clause-views
 * Copyright(c) 2021-2023 Missing Link Electronics, Inc.
 * Copyright(c) 2019 The Regents of the University of California
 */

#include "rte_eth_mqnic.h"

int
mqnic_create_sched_block(struct mqnic_if *interface,
				struct mqnic_sched_block **block_ptr,
				int index,
				struct mqnic_reg_block *block_rb)
{
	PMD_INIT_FUNC_TRACE();
	struct rte_eth_dev *dev = interface->dev;
	struct mqnic_sched_block *block;
	struct mqnic_reg_block *rb;
	uint32_t offset;
	int ret = 0;

	block = rte_zmalloc("Scheduler block", sizeof(*block), RTE_CACHE_LINE_SIZE);
	if (!block)
		return -ENOMEM;

	*block_ptr = block;

	block->dev = dev;
	block->interface = interface;

	block->index = index;

	block->tx_queue_count = interface->tx_queue_count;

	block->block_rb = block_rb;

	offset = rte_read32(block_rb->regs + MQNIC_RB_SCHED_BLOCK_REG_OFFSET);

	block->rb_list = mqnic_enumerate_reg_block_list(interface->hw_addr, offset,
							interface->hw_regs_size - offset);

	if (!block->rb_list) {
		ret = -EIO;
		PMD_INIT_LOG(ERR, "Failed to enumerate blocks");
		goto fail;
	}

	PMD_INIT_LOG(NOTICE, "Scheduler block-level register blocks:");
	for (rb = block->rb_list; rb->regs; rb++)
		PMD_INIT_LOG(NOTICE, " type 0x%08x (v %d.%d.%d.%d)", rb->type, rb->version >> 24,
				(rb->version >> 16) & 0xff,
				(rb->version >> 8) & 0xff, rb->version & 0xff);

	block->sched_count = 0;
	for (rb = block->rb_list; rb->regs; rb++) {
		if (rb->type == MQNIC_RB_SCHED_RR_TYPE && rb->version == MQNIC_RB_SCHED_RR_VER) {
			ret = mqnic_create_scheduler(block, &block->sched[block->sched_count],
							block->sched_count, rb);

			if (ret)
				goto fail;

			block->sched_count++;
		}
	}

	PMD_INIT_LOG(NOTICE, "Scheduler count: %d", block->sched_count);

	mqnic_deactivate_sched_block(block);

	return 0;

fail:
	mqnic_destroy_sched_block(block_ptr);
	return ret;
}

void
mqnic_destroy_sched_block(struct mqnic_sched_block **block_ptr)
{
	struct mqnic_sched_block *block = *block_ptr;
	size_t k;

	mqnic_deactivate_sched_block(block);

	for (k = 0; k < ARRAY_SIZE(block->sched); k++)
		if (block->sched[k])
			mqnic_destroy_scheduler(&block->sched[k]);

	if (block->rb_list)
		mqnic_free_reg_block_list(block->rb_list);

	*block_ptr = NULL;
	rte_free(block);
}

int
mqnic_activate_sched_block(struct mqnic_sched_block *block)
{
	size_t k;

	// enable schedulers
	for (k = 0; k < ARRAY_SIZE(block->sched); k++)
		if (block->sched[k])
			mqnic_scheduler_enable(block->sched[k]);

	return 0;
}

void
mqnic_deactivate_sched_block(struct mqnic_sched_block *block)
{
	size_t k;

	// disable schedulers
	for (k = 0; k < ARRAY_SIZE(block->sched); k++)
		if (block->sched[k])
			mqnic_scheduler_disable(block->sched[k]);
}
