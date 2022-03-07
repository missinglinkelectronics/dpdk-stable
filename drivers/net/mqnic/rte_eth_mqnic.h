/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) 2021-2022 Missing Link Electronics, Inc.
 * Copyright(c) 2019 The Regents of the University of California
 */

#include "mqnic_hw.h"
#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <rte_string_fns.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_io.h>

#include <rte_interrupts.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_branch_prediction.h>
#include <rte_memory.h>
#include <rte_kvargs.h>
#include <rte_eal.h>
#include <rte_alarm.h>
#include <rte_ether.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_pci.h>
#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_mempool.h>
#include <rte_dev.h>

#define IOMEM

#define PAGE_SIZE 0x1000
#define ETH_LEN 14

int mqnic_logtype_init;
#define PMD_INIT_LOG(level, fmt, args...) \
        rte_log(RTE_LOG_ ## level, mqnic_logtype_init, \
                "%s(): " fmt "\n", __func__, ##args)

#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

#define MQNIC_DEV_PRIVATE_TO_HW(adapter) \
	(&((struct mqnic_adapter *)adapter)->hw)

#define MQNIC_DEV_PRIVATE_TO_IFHW(adapter) \
	(&((struct mqnic_adapter *)adapter)->ifhw)

struct mqnic_frag {
    uint64_t dma_addr;
    uint32_t len;
};

struct mqnic_tx_info {
    struct rte_mbuf *page;
    uint64_t dma_addr;
    uint32_t len;
    uint32_t frag_count;
    struct mqnic_frag frags[MQNIC_MAX_FRAGS-1];
    int ts_requested;
};

struct mqnic_rx_info {
    struct rte_mbuf *page;
    uint32_t page_order;
    uint32_t page_offset;
    uint64_t dma_addr;
    uint32_t len;
};

struct mqnic_ring {
    // written on enqueue (i.e. start_xmit)
    uint32_t head_ptr;
    uint64_t bytes;
    uint64_t packets;
    uint64_t dropped_packets;

    // written from completion
    uint32_t tail_ptr ;
    uint32_t clean_tail_ptr;
    uint64_t ts_s;
    uint8_t ts_valid;

    // mostly constant
    uint32_t size;
    uint32_t full_size;
    uint32_t size_mask;
    uint32_t stride;

    uint32_t cpl_index;

    uint16_t mtu;
    uint32_t page_order;

    uint32_t desc_block_size;
    uint32_t log_desc_block_size;

    size_t buf_size;
    uint8_t *buf;
    uint64_t ring_phys_addr; /**<ring DMA address. */

    union {
        struct mqnic_tx_info *tx_info;
        struct mqnic_rx_info *rx_info;
    };

    uint32_t hw_ptr_mask;
    uint8_t  *hw_addr;
    uint8_t  *hw_head_ptr;
    uint8_t  *hw_tail_ptr;
    struct rte_mempool *mp;
    struct rte_eth_dev *dev;
};

struct mqnic_cq_ring {
    uint32_t head_ptr;

    uint32_t tail_ptr;

    uint32_t size;
    uint32_t size_mask;
    uint32_t stride;

    size_t buf_size;
    uint8_t *buf;
    uint64_t ring_phys_addr; /**< ring DMA address. */

    int ring_index;
    int eq_index;

    void (*handler) (struct mqnic_cq_ring *);

    uint32_t hw_ptr_mask;
    uint8_t  *hw_addr;
    uint8_t  *hw_head_ptr;
    uint8_t  *hw_tail_ptr;
    struct rte_eth_dev *dev;
};

struct mqnic_port {
    int index;

    uint32_t tx_queue_count;

    uint32_t port_id;
    uint32_t port_features;
    uint16_t port_mtu;
    uint32_t sched_count;
    uint32_t sched_offset;
    uint32_t sched_stride;
    uint32_t sched_type;

    uint8_t  *hw_addr;
    struct rte_eth_dev *dev;
};

struct mqnic_hw {
	uint8_t IOMEM *hw_addr;

	uint16_t device_id;
	uint16_t vendor_id;

	uint32_t fw_id;
    uint32_t fw_ver;
    uint32_t board_id;
    uint32_t board_ver;

    uint32_t phc_count;
    uint32_t phc_offset;
	uint32_t phc_stride;

    uint32_t if_count;
    uint32_t if_stride;
    uint32_t if_csr_offset;
};

struct mqnic_ifhw {
    uint8_t *csr_hw_addr;
    uint8_t *hw_addr;

    bool registered;
    int port;
    bool port_up;

    uint32_t if_id;
    uint32_t if_features;
    uint32_t event_queue_count;
    uint32_t event_queue_offset;
    uint32_t tx_queue_count;
    uint32_t tx_queue_offset;
    uint32_t tx_cpl_queue_count;
    uint32_t tx_cpl_queue_offset;
    uint32_t rx_queue_count;
    uint32_t rx_queue_offset;
    uint32_t rx_cpl_queue_count;
    uint32_t rx_cpl_queue_offset;
    uint32_t port_count;
    uint32_t port_offset;
    uint32_t port_stride;

    uint32_t max_desc_block_size;

    uint16_t max_mtu;

    struct mqnic_ring *tx_ring[MQNIC_MAX_TX_RINGS];
    struct mqnic_cq_ring *tx_cpl_ring[MQNIC_MAX_TX_CPL_RINGS];
    struct mqnic_ring *rx_ring[MQNIC_MAX_RX_RINGS];
    struct mqnic_cq_ring *rx_cpl_ring[MQNIC_MAX_RX_CPL_RINGS];
    struct mqnic_port *ports[MQNIC_MAX_PORTS];
};

struct mqnic_adapter {
	struct mqnic_hw hw; // Need to be replaced with global struct
	struct mqnic_ifhw ifhw;

};

struct pkt_rx_queue {
	int sockfd;

	struct iovec *rd;
	uint8_t *map;
	unsigned int framecount;
	unsigned int framenum;

	struct rte_mempool *mb_pool;
	uint16_t in_port;

	volatile unsigned long rx_pkts;
	volatile unsigned long rx_bytes;
};

struct pkt_tx_queue {
	int sockfd;
	unsigned int frame_data_size;

	struct iovec *rd;
	uint8_t *map;
	unsigned int framecount;
	unsigned int framenum;

	volatile unsigned long tx_pkts;
	volatile unsigned long err_pkts;
	volatile unsigned long tx_bytes;
};

// mqnic_port.c
int mqnic_create_port(struct rte_eth_dev *dev, struct mqnic_port **port_ptr, int index, uint8_t *hw_addr);
void mqnic_destroy_port(struct rte_eth_dev *dev, struct mqnic_port **port_ptr);
int mqnic_activate_port(struct mqnic_port *port);
void mqnic_deactivate_port(struct mqnic_port *port);
uint32_t mqnic_port_get_rss_mask(struct mqnic_port *port);
void mqnic_port_set_rss_mask(struct mqnic_port *port, uint32_t rss_mask);
uint32_t mqnic_port_get_tx_mtu(struct mqnic_port *port);
void mqnic_port_set_tx_mtu(struct mqnic_port *port, uint32_t mtu);
uint32_t mqnic_port_get_rx_mtu(struct mqnic_port *port);
void mqnic_port_set_rx_mtu(struct mqnic_port *port, uint32_t mtu);

// mqnic_cq.c
int mqnic_create_cq_ring(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc, unsigned int socket_id, struct rte_mempool *mp, bool is_tx);
void mqnic_destroy_cq_ring(struct rte_eth_dev *dev, struct mqnic_cq_ring **ring_ptr, bool is_tx);
int mqnic_activate_cq_ring(struct rte_eth_dev *dev, struct mqnic_cq_ring *ring, int eq_index);
void mqnic_deactivate_cq_ring(struct rte_eth_dev *dev, struct mqnic_cq_ring *ring);
bool mqnic_is_cq_ring_empty(const struct mqnic_cq_ring *ring);
bool mqnic_is_cq_ring_full(const struct mqnic_cq_ring *ring);
void mqnic_cq_read_head_ptr(struct mqnic_cq_ring *ring);
void mqnic_cq_write_tail_ptr(struct mqnic_cq_ring *ring);

// mqnic_tx.c
int mqnic_create_tx_ring(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc, unsigned int socket_id, const struct rte_eth_txconf *tx_conf);
void mqnic_destroy_tx_ring(struct rte_eth_dev *dev, struct mqnic_ring **ring_ptr);
int mqnic_activate_tx_ring(struct rte_eth_dev *dev, struct mqnic_ring *ring, int cpl_index);
void mqnic_deactivate_tx_ring(struct rte_eth_dev *dev, struct mqnic_ring *ring);
bool mqnic_is_tx_ring_empty(const struct mqnic_ring *ring);
bool mqnic_is_tx_ring_full(const struct mqnic_ring *ring);
void mqnic_tx_read_tail_ptr(struct mqnic_ring *ring);
void mqnic_tx_write_head_ptr(struct mqnic_ring *ring);
void mqnic_free_tx_desc(struct rte_eth_dev *dev, struct mqnic_ring *ring, int index, int napi_budget);
int mqnic_free_tx_buf(struct rte_eth_dev *dev, struct mqnic_ring *ring);
int mqnic_process_tx_cq(struct mqnic_ring *cq_ring, struct rte_mbuf **bufs, uint16_t nb_pkts);
int mqnic_poll_tx_cq(int budget);
int mqnic_start_xmit(struct mqnic_ring *tx_ring, struct rte_mbuf **mbuf, int num_packets);

// mqnic_rx.c
int mqnic_create_rx_ring(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc, unsigned int socket_id, const struct rte_eth_rxconf *rx_conf, struct rte_mempool *mp);
void mqnic_destroy_rx_ring(struct rte_eth_dev *dev, struct mqnic_ring **ring_ptr);
int mqnic_activate_rx_ring(struct rte_eth_dev *dev, struct mqnic_ring *ring, int cpl_index);
void mqnic_deactivate_rx_ring(struct rte_eth_dev *dev, struct mqnic_ring *ring);
bool mqnic_is_rx_ring_empty(const struct mqnic_ring *ring);
bool mqnic_is_rx_ring_full(const struct mqnic_ring *ring);
void mqnic_rx_read_tail_ptr(struct mqnic_ring *ring);
void mqnic_rx_write_head_ptr(struct mqnic_ring *ring);
void mqnic_free_rx_desc(struct rte_eth_dev *dev, struct mqnic_ring *ring, int index);
int mqnic_free_rx_buf(struct rte_eth_dev *dev, struct mqnic_ring *ring);
int mqnic_prepare_rx_desc(struct rte_eth_dev *dev, struct mqnic_ring *ring, int index);
void mqnic_refill_rx_buffers(struct rte_eth_dev *dev, struct mqnic_ring *ring);
int mqnic_process_rx_cq(struct mqnic_ring *rx_ring, int napi_budget, struct rte_mbuf **bufs);
int mqnic_poll_rx_cq(int budget);

void mqnic_debug_write(uint32_t value, uint8_t *addr, struct rte_eth_dev *dev, const char *message);
