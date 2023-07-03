/* SPDX-License-Identifier: BSD-2-Clause-views
 * Copyright(c) 2021-2023 Missing Link Electronics, Inc.
 * Copyright(c) 2019 The Regents of the University of California
 */

#include "rte_eth_mqnic.h"

int
mqnic_create_scheduler(struct mqnic_sched_block *block,
			struct mqnic_sched **sched_ptr,
			int index,
			struct mqnic_reg_block *rb)
{
	PMD_INIT_FUNC_TRACE();
	struct rte_eth_dev *dev = block->dev;
	struct mqnic_sched *sched;

	sched = rte_zmalloc("Scheduler", sizeof(*sched), RTE_CACHE_LINE_SIZE);
	if (!sched)
		return -ENOMEM;

	*sched_ptr = sched;

	sched->dev = dev;
	sched->interface = block->interface;
	sched->sched_block = block;

	sched->index = index;

	sched->rb = rb;

	sched->type = rb->type;
	sched->offset = rte_read32(rb->regs + MQNIC_RB_SCHED_RR_REG_OFFSET);
	sched->channel_count = rte_read32(rb->regs + MQNIC_RB_SCHED_RR_REG_CH_COUNT);
	sched->channel_stride = rte_read32(rb->regs + MQNIC_RB_SCHED_RR_REG_CH_STRIDE);

	sched->hw_addr = block->interface->hw_addr + sched->offset;

	PMD_INIT_LOG(NOTICE, "Scheduler type: 0x%08x", sched->type);
	PMD_INIT_LOG(NOTICE, "Scheduler offset: 0x%08x", sched->offset);
	PMD_INIT_LOG(NOTICE, "Scheduler channel count: %d", sched->channel_count);
	PMD_INIT_LOG(NOTICE, "Scheduler channel stride: 0x%08x", sched->channel_stride);

	mqnic_scheduler_disable(sched);

	return 0;
}

void
mqnic_destroy_scheduler(struct mqnic_sched **sched_ptr)
{
	struct mqnic_sched *sched = *sched_ptr;
	*sched_ptr = NULL;

	mqnic_scheduler_disable(sched);

	rte_free(sched);
}

int
mqnic_scheduler_enable(struct mqnic_sched *sched)
{
	size_t k;

	// enable scheduler
	rte_write32(1, sched->rb->regs + MQNIC_RB_SCHED_RR_REG_CTRL);

	// enable queues
	for (k = 0; k < sched->channel_count; k++)
		rte_write32(3, sched->hw_addr + k * sched->channel_stride);

	return 0;
}

void
mqnic_scheduler_disable(struct mqnic_sched *sched)
{
	// disable scheduler
	rte_write32(0, sched->rb->regs + MQNIC_RB_SCHED_RR_REG_CTRL);
}
