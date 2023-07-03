/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) 2021-2023 Missing Link Electronics, Inc.
 * Copyright(c) 2019 The Regents of the University of California
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <rte_alarm.h>
#include <rte_branch_prediction.h>
#include <ethdev_pci.h>
#include <ethdev_driver.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_io.h>
#include <rte_kvargs.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_string_fns.h>

#include "mqnic_hw.h"

#define IOMEM

#define PAGE_SIZE	0x1000
#define ETH_LEN		14

extern int mqnic_logtype_init;
#define PMD_INIT_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_##level, mqnic_logtype_init, "%s(): " fmt "\n", __func__, ##args)

#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

#define MQNIC_DEV_PRIVATE(adapter) (struct mqnic_priv *)adapter

#define MQNIC_DEV_PRIVATE_TO_IFHW(adapter) ((struct mqnic_priv *)adapter)->interface

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))


extern unsigned int mqnic_num_ev_queue_entries;
extern unsigned int mqnic_num_tx_queue_entries;
extern unsigned int mqnic_num_rx_queue_entries;

extern unsigned int mqnic_link_status_poll;

struct mqnic_dev;
struct mqnic_if;

struct mqnic_reg_block {
	uint32_t	type;
	uint32_t	version;
	uint8_t IOMEM	*regs;
	uint8_t IOMEM	*base;
};

struct mqnic_board_ops {
	int (*init)(struct mqnic_dev *mqnic);
	void (*deinit)(struct mqnic_dev *mqnic);
};

struct mqnic_dev {
	uint64_t	hw_regs_size;
	phys_addr_t	hw_regs_phys;
	uint8_t IOMEM	*hw_addr;
	uint8_t IOMEM	*phc_hw_addr;

	uint64_t	app_hw_regs_size;
	phys_addr_t	app_hw_regs_phys;
	uint8_t IOMEM	*app_hw_addr;

	uint64_t	ram_hw_regs_size;
	phys_addr_t	ram_hw_regs_phys;
	uint8_t IOMEM	*ram_hw_addr;

	int		mac_count;

	char		name[16];

	unsigned int	id;
	unsigned int	initialised;

	struct mqnic_reg_block	*rb_list;
	struct mqnic_reg_block	*fw_id_rb;
	struct mqnic_reg_block	*if_rb;
	struct mqnic_reg_block	*phc_rb;

	int	dev_port_max;
	int	dev_port_limit;

	uint32_t	fpga_id;
	uint32_t	fw_id;
	uint32_t	fw_ver;
	uint32_t	board_id;
	uint32_t	board_ver;
	uint32_t	build_date;
	uint32_t	git_hash;
	uint32_t	rel_info;

	uint32_t	app_id;

	uint32_t	if_offset;
	uint32_t	if_count;
	uint32_t	if_stride;
	uint32_t	if_csr_offset;

	struct mqnic_if	*interface[MQNIC_MAX_IF];

	struct mqnic_board_ops	*board_ops;
};

struct mqnic_frag {
	uint64_t	dma_addr;
	uint32_t	len;
};

struct mqnic_tx_info {
	struct rte_mbuf	*page;
	uint64_t	dma_addr;
	uint32_t	len;
	uint32_t	frag_count;

	struct mqnic_frag frags[MQNIC_MAX_FRAGS - 1];
	
	int	ts_requested;
};

struct mqnic_rx_info {
	struct rte_mbuf	*page;
	uint32_t	page_order;
	uint32_t	page_offset;
	uint64_t	dma_addr;
	uint32_t	len;
};

struct mqnic_ring {
	// written on enqueue (i.e. start_xmit)
	uint32_t	head_ptr;
	uint64_t	bytes;
	uint64_t	packets;
	uint64_t	dropped_packets;

	// written from completion
	uint32_t	tail_ptr;
	uint32_t	clean_tail_ptr;
	uint64_t	ts_s;
	uint8_t		ts_valid;

	// mostly constant
	uint32_t	size;
	uint32_t	full_size;
	uint32_t	size_mask;
	uint32_t	stride;

	uint32_t	cpl_index;

	uint16_t	mtu;
	uint32_t	page_order;

	uint32_t	desc_block_size;
	uint32_t	log_desc_block_size;

	size_t		buf_size;
	uint8_t		*buf;
	uint64_t	ring_phys_addr; /**<ring DMA address. */

	union {
		struct mqnic_tx_info	*tx_info;
		struct mqnic_rx_info	*rx_info;
	};

	uint32_t	hw_ptr_mask;
	uint8_t		*hw_addr;
	uint8_t		*hw_head_ptr;
	uint8_t		*hw_tail_ptr;

	struct rte_mempool	*mp;

	struct rte_eth_dev	*dev;
	struct mqnic_if		*interface;
	struct mqnic_priv	*priv;
	int			index;
	struct mqnic_cq_ring	*cq_ring;
	int			active;
};

struct mqnic_cq_ring {
	uint32_t	head_ptr;

	uint32_t	tail_ptr;

	uint32_t	size;
	uint32_t	size_mask;
	uint32_t	stride;

	size_t		buf_size;
	uint8_t		*buf;
	uint64_t	ring_phys_addr; /**< ring DMA address. */

	struct rte_eth_dev	*dev;
	struct mqnic_if		*interface;
	int			ring_index;
	int			eq_index;
	struct mqnic_eq_ring	*eq_ring;
	struct mqnic_ring	*src_ring;
	int			active;

	void (*handler)(struct mqnic_cq_ring *);

	uint32_t	hw_ptr_mask;
	uint8_t		*hw_addr;
	uint8_t		*hw_head_ptr;
	uint8_t		*hw_tail_ptr;
};


struct mqnic_sched {
	struct rte_eth_dev	*dev;
	struct mqnic_if		*interface;

	struct mqnic_sched_block	*sched_block;

	struct mqnic_reg_block	*rb;

	int	index;

	uint32_t	type;
	uint32_t	offset;
	uint32_t	channel_count;
	uint32_t	channel_stride;

	uint8_t	*hw_addr;
};

struct mqnic_port {
	struct rte_eth_dev	*dev;
	struct mqnic_if		*interface;

	struct mqnic_reg_block	*port_rb;
	struct mqnic_reg_block	*rb_list;
	struct mqnic_reg_block	*port_ctrl_rb;

	int	index;

	uint32_t	port_features;
};

struct mqnic_sched_block {
	struct rte_eth_dev	*dev;
	struct mqnic_if		*interface;

	struct mqnic_reg_block	*block_rb;
	struct mqnic_reg_block	*rb_list;

	int	index;

	uint32_t	tx_queue_count;

	uint32_t	sched_count;
	struct mqnic_sched	*sched[MQNIC_MAX_PORTS];
};

struct pkt_rx_queue {
	int	sockfd;

	struct iovec	*rd;
	uint8_t		*map;
	unsigned int	framecount;
	unsigned int	framenum;

	struct rte_mempool	*mb_pool;
	uint16_t		in_port;

	volatile unsigned long	rx_pkts;
	volatile unsigned long	rx_bytes;
};

struct pkt_tx_queue {
	int		sockfd;
	unsigned int	frame_data_size;

	struct iovec	*rd;
	uint8_t		*map;
	unsigned int	framecount;
	unsigned int	framenum;

	volatile unsigned long	tx_pkts;
	volatile unsigned long	err_pkts;
	volatile unsigned long	tx_bytes;
};

struct mqnic_if {
	struct rte_eth_dev	*dev;
	struct mqnic_dev	*mdev;

	struct mqnic_reg_block	*rb_list;
	struct mqnic_reg_block	*if_ctrl_rb;
	struct mqnic_reg_block	*event_queue_rb;
	struct mqnic_reg_block	*tx_queue_rb;
	struct mqnic_reg_block	*tx_cpl_queue_rb;
	struct mqnic_reg_block	*rx_queue_rb;
	struct mqnic_reg_block	*rx_cpl_queue_rb;
	struct mqnic_reg_block	*rx_queue_map_rb;

	int	index;

	int	dev_port_base;
	int	dev_port_max;
	int	dev_port_limit;

	uint32_t	if_features;

	uint32_t	max_tx_mtu;
	uint32_t	max_rx_mtu;
	uint32_t	tx_mtu;
	uint32_t	rx_mtu;

	uint32_t		tx_queue_offset;
	uint32_t		tx_queue_count;
	uint32_t		tx_queue_stride;
	struct mqnic_ring	*tx_ring[MQNIC_MAX_TX_RINGS];

	uint32_t		tx_cpl_queue_offset;
	uint32_t		tx_cpl_queue_count;
	uint32_t		tx_cpl_queue_stride;
	struct mqnic_cq_ring	*tx_cpl_ring[MQNIC_MAX_TX_CPL_RINGS];

	uint32_t		rx_queue_offset;
	uint32_t		rx_queue_count;
	uint32_t		rx_queue_stride;
	struct mqnic_ring	*rx_ring[MQNIC_MAX_RX_RINGS];

	uint32_t		rx_cpl_queue_offset;
	uint32_t		rx_cpl_queue_count;
	uint32_t		rx_cpl_queue_stride;
	struct mqnic_cq_ring	*rx_cpl_ring[MQNIC_MAX_RX_CPL_RINGS];

	uint32_t		port_count;
	struct mqnic_port	*port[MQNIC_MAX_PORTS];

	uint32_t			sched_block_count;
	struct mqnic_sched_block	*sched_block[MQNIC_MAX_PORTS];

	uint32_t	max_desc_block_size;

	uint64_t	hw_regs_size;
	uint8_t IOMEM	*hw_addr;
	uint8_t IOMEM	*csr_hw_addr;
};

struct mqnic_priv {
	struct rte_eth_dev	*dev;
	struct mqnic_dev	*mdev;
	struct mqnic_if		*interface;

	int	index;
	bool	registered;
	bool	port_up;

	uint32_t	if_features;

	unsigned int	link_status;

	uint32_t		tx_queue_count;
	struct mqnic_ring	*tx_ring[MQNIC_MAX_TX_RINGS];

	uint32_t		tx_cpl_queue_count;
	struct mqnic_cq_ring	*tx_cpl_ring[MQNIC_MAX_TX_CPL_RINGS];

	uint32_t		rx_queue_count;
	struct mqnic_ring	*rx_ring[MQNIC_MAX_RX_RINGS];

	uint32_t		rx_cpl_queue_count;
	struct mqnic_cq_ring	*rx_cpl_ring[MQNIC_MAX_RX_CPL_RINGS];

	uint32_t			sched_block_count;
	struct mqnic_sched_block	*sched_block[MQNIC_MAX_PORTS];

	uint32_t	max_desc_block_size;
};

// mqnic_reg_block.c
struct mqnic_reg_block *mqnic_enumerate_reg_block_list(uint8_t *base,
	size_t offset,
	size_t size);
struct mqnic_reg_block *mqnic_find_reg_block(struct mqnic_reg_block *list,
	uint32_t type,
	uint32_t version,
	int index);
void mqnic_free_reg_block_list(struct mqnic_reg_block *list);

// mqnic_if.c
int mqnic_create_interface(struct mqnic_dev *mdev,
	struct mqnic_if **interface_ptr,
	int index,
	uint8_t *hw_addr);
void mqnic_destroy_interface(struct mqnic_if **interface_ptr);
uint32_t mqnic_interface_get_tx_mtu(struct mqnic_if *interface);
void mqnic_interface_set_tx_mtu(struct mqnic_if *interface, uint32_t mtu);
uint32_t mqnic_interface_get_rx_mtu(struct mqnic_if *interface);
void mqnic_interface_set_rx_mtu(struct mqnic_if *interface, uint32_t mtu);
uint32_t mqnic_interface_get_rx_queue_map_offset(struct mqnic_if *interface,
	int port);
void mqnic_interface_set_rx_queue_map_offset(struct mqnic_if *interface,
	int port,
	uint32_t val);
uint32_t mqnic_interface_get_rx_queue_map_rss_mask(struct mqnic_if *interface,
	int port);
void mqnic_interface_set_rx_queue_map_rss_mask(struct mqnic_if *interface,
	int port,
	uint32_t val);
uint32_t mqnic_interface_get_rx_queue_map_app_mask(struct mqnic_if *interface,
	int port);
void mqnic_interface_set_rx_queue_map_app_mask(struct mqnic_if *interface,
	int port,
	uint32_t val);

// mqnic_port.c
int
mqnic_create_port(struct mqnic_if *interface, struct mqnic_port **port_ptr,
	int index,
	struct mqnic_reg_block *port_rb);
void mqnic_destroy_port(struct mqnic_port **port_ptr);
uint32_t mqnic_port_get_tx_status(struct mqnic_port *port);
uint32_t mqnic_port_get_rx_status(struct mqnic_port *port);

// mqnic_cq.c
int mqnic_create_cq_ring(struct mqnic_if *interface,
	struct mqnic_cq_ring **ring_ptr_if,
	struct mqnic_cq_ring **ring_ptr_priv,
	int index,
	uint8_t *hw_addr);
int mqnic_alloc_cq_ring(struct rte_eth_dev *dev, struct mqnic_cq_ring *ring,
	int size,
	int stride,
	bool is_tx);
void mqnic_destroy_cq_ring(struct rte_eth_dev *dev,
	struct mqnic_cq_ring *ring_ptr,
	bool is_tx);
int mqnic_activate_cq_ring(struct mqnic_cq_ring *ring, int eq_index);
void mqnic_deactivate_cq_ring(struct mqnic_cq_ring *ring);
bool mqnic_is_cq_ring_empty(const struct mqnic_cq_ring *ring);
bool mqnic_is_cq_ring_full(const struct mqnic_cq_ring *ring);
void mqnic_cq_read_head_ptr(struct mqnic_cq_ring *ring);
void mqnic_cq_write_tail_ptr(struct mqnic_cq_ring *ring);
void mqnic_arm_cq(struct mqnic_cq_ring *ring);

// mqnic_tx.c
int mqnic_create_tx_ring(struct mqnic_if *interface,
	struct mqnic_ring **ring_ptr_if,
	struct mqnic_ring **ring_ptr_priv,
	uint16_t queue_idx,
	uint8_t *hw_addr,
	__rte_unused const struct rte_eth_txconf *tx_conf);
int mqnic_alloc_tx_ring(struct rte_eth_dev *dev, struct mqnic_ring *txq,
	int size,
	int stride);
void mqnic_destroy_tx_ring(struct rte_eth_dev *dev,
	struct mqnic_ring *ring_ptr);
int mqnic_activate_tx_ring(struct mqnic_ring *ring, int cpl_index);
void mqnic_deactivate_tx_ring(struct mqnic_ring *ring);
bool mqnic_is_tx_ring_empty(const struct mqnic_ring *ring);
bool mqnic_is_tx_ring_full(const struct mqnic_ring *ring);
void mqnic_tx_read_tail_ptr(struct mqnic_ring *ring);
void mqnic_tx_write_head_ptr(struct mqnic_ring *ring);
void mqnic_free_tx_desc(struct mqnic_ring *ring, int index);
int mqnic_free_tx_buf(struct mqnic_ring *ring);
int mqnic_process_tx_cq(struct mqnic_ring *cq_ring);
int mqnic_poll_tx_cq(int budget);
bool mqnic_start_xmit(struct mqnic_ring *tx_ring, struct rte_mbuf *mbuf);

// mqnic_rx.c
int mqnic_create_rx_ring(struct mqnic_if *interface,
	struct mqnic_ring **ring_ptr_if,
	struct mqnic_ring **ring_ptr_priv,
	uint16_t queue_idx,
	uint8_t *hw_addr,
	__rte_unused const struct rte_eth_rxconf *rx_conf,
	struct rte_mempool *mp);
int mqnic_alloc_rx_ring(struct rte_eth_dev *dev, struct mqnic_ring *rxq,
	int size,
	int stride);
void mqnic_destroy_rx_ring(struct rte_eth_dev *dev,
	struct mqnic_ring *ring_ptr);
int mqnic_activate_rx_ring(struct rte_eth_dev *dev, struct mqnic_ring *ring,
	int cpl_index);
void mqnic_deactivate_rx_ring(struct mqnic_ring *ring);
bool mqnic_is_rx_ring_empty(const struct mqnic_ring *ring);
bool mqnic_is_rx_ring_full(const struct mqnic_ring *ring);
void mqnic_rx_read_tail_ptr(struct mqnic_ring *ring);
void mqnic_rx_write_head_ptr(struct mqnic_ring *ring);
void mqnic_free_rx_desc(struct mqnic_ring *ring, int index);
int mqnic_free_rx_buf(struct mqnic_ring *ring);
int mqnic_prepare_rx_desc(struct rte_eth_dev *dev, struct mqnic_ring *ring,
	int index);
void mqnic_refill_rx_buffers(struct rte_eth_dev *dev, struct mqnic_ring *ring);
int mqnic_process_rx_cq(struct mqnic_ring *rx_ring, int napi_budget,
	struct rte_mbuf **bufs);
int mqnic_poll_rx_cq(int budget);

// mqnic_sched_block.c
int mqnic_create_sched_block(struct mqnic_if *interface,
	struct mqnic_sched_block **block_ptr,
	int index,
	struct mqnic_reg_block *rb);
void mqnic_destroy_sched_block(struct mqnic_sched_block **block_ptr);
int mqnic_activate_sched_block(struct mqnic_sched_block *block);
void mqnic_deactivate_sched_block(struct mqnic_sched_block *block);

// mqnic_scheduler.c
int mqnic_create_scheduler(struct mqnic_sched_block *block,
	struct mqnic_sched **sched_ptr,
	int index,
	struct mqnic_reg_block *rb);
void mqnic_destroy_scheduler(struct mqnic_sched **sched_ptr);
int mqnic_scheduler_enable(struct mqnic_sched *sched);
void mqnic_scheduler_disable(struct mqnic_sched *sched);
