#include <pcap.h>

#include "common.h"

#include <rte_pci.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#define DEBUG

#ifdef DEBUG
#define debug printf
#else
#define debug
#endif

static const char pcap_version_string[] = "dpdk pcap version 0.1";
static char errbuf_g[PCAP_ERRBUF_SIZE];

//#define VER_16

#define DPDKPCAP_MBUF_SIZE       (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define DPDKPCAP_NB_MBUF         512
#define DPDKPCAP_CACHE_SIZE      32
#define DPDKPCAP_RX_QUEUE_NUMBER 1
#define DPDKPCAP_TX_QUEUE_NUMBER 1
#define DPDKPCAP_IF_NAMESIZE     16

static char ifName [DPDKPCAP_IF_NAMESIZE];

#define PACKET_COUNT_IS_UNLIMITED(count)	((count) <= 0)

int initFinished = 0;
int portInitFinished[RTE_MAX_ETHPORTS] = {0};

struct rte_mempool* rxPool = 0;
#define DPDKPCAP_RX_POOL_NAME "RX_POOL"
#define DPDKPCAP_RX_QUEUE_DESC_NUMBER 128

struct rte_mempool* txPool = 0;
#define DPDKPCAP_TX_POOL_NAME "TX_POOL"
#define DPDKPCAP_TX_QUEUE_DESC_NUMBER 128

#define DEVICE_NAME_SIZE 16

char* deviceNames[RTE_MAX_ETHPORTS] = {NULL};

#define PACKET_SIZE 10000

static u_char data_g[PACKET_SIZE];
static struct pcap_pkthdr pktHeader_g;

#define DEF_PKT_BURST 32
static struct rte_mbuf* mbuf_g[DEF_PKT_BURST];

int linkStatusGet(const char* device)
{
    int deviceId = 0;
    struct rte_eth_link link;

    if (device == NULL)
    {
        snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Invalid parameter");
        return DPDKPCAP_FAILURE;
    }

    deviceId = findDevice(device, errbuf_g);

    rte_eth_link_get_nowait(deviceId, &link);

    return link.link_status;
}

static void
lsi_event_callback(uint8_t port_id, enum rte_eth_event_type type, void *param)
{
    struct rte_eth_link link;

    RTE_SET_USED(param);

    printf("\n\nIn registered callback...\n");
    printf("Event type: %s\n", type == RTE_ETH_EVENT_INTR_LSC ? "LSC interrupt" : "unknown event");
    rte_eth_link_get_nowait(port_id, &link);
    if (link.link_status) {
        printf("Port %d Link Up - speed %u Mbps - %s\n\n",
                port_id, (unsigned)link.link_speed,
            (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                ("full-duplex") : ("half-duplex"));
    } else
        printf("Port %d Link Down\n\n", port_id);
}

int rxStatsGet(pcap_t *p)
{
    struct rte_eth_stats stats;

    if (p == NULL || p->deviceId < 0 ||
        p->deviceId > RTE_MAX_ETHPORTS)
    {
        snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Invalid parameter");
        return DPDKPCAP_FAILURE;
    }

    rte_eth_stats_get(p->deviceId, &stats);

    debug("\nRX port %hu: rx: %"PRIu64 " err: %"PRIu64 " no_mbuf: %"PRIu64 "\n",
           p->deviceId, stats.ipackets, stats.ierrors, stats.rx_nombuf);

    return stats.ipackets;
}

int txStatsGet(pcap_t *p)
{
    struct rte_eth_stats stats;

    if (p == NULL || p->deviceId < 0 ||
        p->deviceId > RTE_MAX_ETHPORTS)
    {
        snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Invalid parameter");
        return DPDKPCAP_FAILURE;
    }

    rte_eth_stats_get(p->deviceId, &stats);

    debug("\nTX port %hu: tx: %"PRIu64 " err: %"PRIu64 "\n",
           p->deviceId, stats.opackets, stats.oerrors);

    return stats.opackets;
}

DpdkPcapResultCode_t globalInit(char *errbuf)
{
    char *args[] = {"dpdkpcap_test", "-c 0x03", "-n 2", "-m 128", "--file-prefix=dpdkpcap_test"};

    if (initFinished == 1)
    {
        return DPDKPCAP_OK;
    }

    if (rte_eal_init(sizeof(args)/sizeof(char*), args) < 0)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "Could not initialize DPDK");
        return DPDKPCAP_FAILURE;
    }

#ifdef VER_16
    if (rte_pmd_init_all() < 0)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "Could not init driver");
        return DPDKPCAP_FAILURE;
    }
#endif

    if (rte_eal_pci_probe() < 0)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "Could not probe devices");
        return DPDKPCAP_FAILURE;
    }

    rxPool = rte_mempool_create(DPDKPCAP_RX_POOL_NAME,
             DPDKPCAP_NB_MBUF,
             DPDKPCAP_MBUF_SIZE,
             DPDKPCAP_CACHE_SIZE,
             sizeof(struct rte_pktmbuf_pool_private),
             rte_pktmbuf_pool_init, NULL,
             rte_pktmbuf_init, NULL,
             SOCKET_ID_ANY,
             MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);

    if(rxPool == NULL)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "Could not allocate RX memory pool");
        return DPDKPCAP_FAILURE;
    }

    txPool = rte_mempool_create(DPDKPCAP_TX_POOL_NAME,
             DPDKPCAP_NB_MBUF,
             DPDKPCAP_MBUF_SIZE,
             DPDKPCAP_CACHE_SIZE,
             sizeof(struct rte_pktmbuf_pool_private),
             rte_pktmbuf_pool_init, NULL,
             rte_pktmbuf_init, NULL,
             SOCKET_ID_ANY,
             MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);

    if(txPool == NULL)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "Could not allocate TX memory pool");
        return DPDKPCAP_FAILURE;
    }

    initFinished = 1;
    return DPDKPCAP_OK;
}

DpdkPcapResultCode_t deviceInit(int deviceId, char *errbuf)
{
    struct rte_eth_conf portConf;
    struct rte_eth_rxconf rxConf;
    struct rte_eth_txconf txConf;
    int queueId = 0;

    memset(&portConf, 0, sizeof(portConf));
    memset(&rxConf, 0, sizeof(rxConf));
    memset(&txConf, 0, sizeof(txConf));

    if (initFinished == 0)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "Global DPDK init is not performed yet");
        return DPDKPCAP_FAILURE;
    }

    if (portInitFinished[deviceId] == 1)
    {
        return DPDKPCAP_OK;
    }

    portConf.rxmode.split_hdr_size = 0;
    portConf.rxmode.header_split   = 0;
    portConf.rxmode.hw_ip_checksum = 0;
    portConf.rxmode.hw_vlan_filter = 0;
    portConf.rxmode.jumbo_frame    = 0;
    portConf.rxmode.hw_strip_crc   = 0;
    portConf.txmode.mq_mode = ETH_MQ_TX_NONE;

    if (rte_eth_dev_configure(deviceId, DPDKPCAP_RX_QUEUE_NUMBER, DPDKPCAP_TX_QUEUE_NUMBER, &portConf) < 0)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "Could not configure the device %d", deviceId);
        return DPDKPCAP_FAILURE;
    }

    rte_eth_dev_callback_register(deviceId, RTE_ETH_EVENT_INTR_LSC, lsi_event_callback, NULL);

    rxConf.rx_thresh.pthresh = DPDKPCAP_RX_PTHRESH;
    rxConf.rx_thresh.hthresh = DPDKPCAP_RX_HTHRESH;
    rxConf.rx_thresh.wthresh = DPDKPCAP_RX_WTHRESH;

    if (rte_eth_rx_queue_setup(deviceId, queueId, DPDKPCAP_RX_QUEUE_DESC_NUMBER, SOCKET_ID_ANY, &rxConf, rxPool) < 0)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "Could not setup RX queue of the device %d", deviceId);
        return DPDKPCAP_FAILURE;
    }

    txConf.tx_thresh.pthresh = DPDKPCAP_TX_PTHRESH;
    txConf.tx_thresh.hthresh = DPDKPCAP_TX_HTHRESH;
    txConf.tx_thresh.wthresh = DPDKPCAP_TX_WTHRESH;

    if (rte_eth_tx_queue_setup(deviceId, queueId, DPDKPCAP_TX_QUEUE_DESC_NUMBER, SOCKET_ID_ANY, &txConf) < 0)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "Could not setup TX queue of the device %d", deviceId);
        return DPDKPCAP_FAILURE;
    }

    portInitFinished[deviceId] = 1;

    return DPDKPCAP_OK;
}

DpdkPcapResultCode_t deviceDeInit(int deviceId)
{
    if (portInitFinished[deviceId] == 0)
    {
        return DPDKPCAP_FAILURE;
    }

    rte_eth_dev_stop(deviceId);

    portInitFinished[deviceId] = 0;

    return DPDKPCAP_OK;
}

int findDevice(const char *source, char *errbuf)
{
    int i = 0;

    for (i = 0; i < sizeof(deviceNames); i++)
    {
        if (strncmp(source, deviceNames[i], DEVICE_NAME_SIZE) == 0)
            return i;
    }

    snprintf (errbuf, PCAP_ERRBUF_SIZE, "Could not find device %s", source);
    return -1;
}

pcap_t* pcap_open_live(const char *source, int snaplen, int promisc, int to_ms, char *errbuf)
{
    pcap_t *p = NULL;
    int deviceId = 0;

    debug("Opening device %s\n", source);

    if (initFinished == 0)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "Global DPDK init is not performed yet");
        return NULL;
    }

    deviceId = findDevice(source, errbuf);
    if (deviceId < 0)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "Did not find the device %s", source);
        return NULL;
    }

    if (promisc)
        rte_eth_promiscuous_enable(deviceId);
    else
        rte_eth_promiscuous_disable(deviceId);

    if (rte_eth_dev_start(deviceId) < 0)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "Could not start the device %d", deviceId);
        return NULL;
    }

    p = malloc (sizeof(pcap_t));
    memset(p, 0, sizeof(pcap_t));

    p->deviceId = deviceId;

    return p;
}

int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
    return pcap_loop(p, cnt, callback, user);
}

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
    struct pcap_pkthdr *header  = NULL;
    const u_char *pktdata = NULL;
    int ret = 0;

    if (initFinished == 0)
    {
        return DPDKPCAP_FAILURE;
    }

    for (;;)
    {
        ret = pcap_next_ex(p, &header, &pktdata);
        if (ret == 1)
        {
            callback(user, header, pktdata);
        }

        if (!PACKET_COUNT_IS_UNLIMITED(cnt))
        {
            cnt -= ret;
            if (cnt <= 0)
                return DPDKPCAP_OK;
        }
    }

    return DPDKPCAP_FAILURE;
}

void pcap_close(pcap_t *p)
{
    char *deviceName = NULL;

    if (p == NULL || p->deviceId < 0 ||
        p->deviceId > RTE_MAX_ETHPORTS)
    {
        snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Invalid parameter");
        return;
    }

    deviceName = deviceNames[p->deviceId];
    debug("Closing device %s\n", deviceName);

    rte_eth_dev_stop(p->deviceId);

    free(p);
}

char* pcap_lookupdev(char* errbuf)
{
    int    port  = 0;
    struct rte_eth_dev_info info;

    if (globalInit(errbuf) != DPDKPCAP_OK)
    {
        return NULL;
    }

    int portsNumber = rte_eth_dev_count();
    if (portsNumber < 1)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "No devices found");
        return NULL;
    }

    if (deviceInit(port, errbuf) == DPDKPCAP_FAILURE)
    {
        return NULL;
    }

    rte_eth_dev_info_get(port, &info);

    snprintf(ifName, DPDKPCAP_IF_NAMESIZE, "enp%us%u",
             info.pci_dev->addr.bus,
             info.pci_dev->addr.devid);

    deviceNames[port] = ifName;

    return ifName;
}

int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
{
    int       port     = 0;
    pcap_if_t *pPcapIf = NULL;
    pcap_if_t *pPcapPrevious = NULL;
    struct rte_eth_dev_info info;

    if (globalInit(errbuf) != DPDKPCAP_OK)
    {        
        return DPDKPCAP_FAILURE;
    }

    int portsNumber = rte_eth_dev_count();
    if (portsNumber < 1)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "No devices found");
        return DPDKPCAP_FAILURE;
    }

    debug ("Discovered %d devices\n", portsNumber);

    for (port = 0; port < portsNumber; port++)
    {
        if (deviceInit(port, errbuf) == DPDKPCAP_FAILURE)
        {
            return DPDKPCAP_FAILURE;
        }

        pPcapIf = malloc(sizeof(pcap_if_t));
        memset(pPcapIf, 0, sizeof(pcap_if_t));

        if (pPcapPrevious)
            pPcapPrevious->next = pPcapIf;
        else
            *alldevsp = pPcapIf;

        pPcapPrevious = pPcapIf;

        rte_eth_dev_info_get(port, &info);

        pPcapIf->name = malloc(DPDKPCAP_IF_NAMESIZE);
        memset(pPcapIf->name, 0, DPDKPCAP_IF_NAMESIZE);

        snprintf(pPcapIf->name, DPDKPCAP_IF_NAMESIZE, "port%ubus%udev%u",
                 port,
                 info.pci_dev->addr.bus,
                 info.pci_dev->addr.devid);

        deviceNames[port] = pPcapIf->name;

        pPcapIf->description = malloc(DPDKPCAP_IF_NAMESIZE);
        memset(pPcapIf->description, 0, DPDKPCAP_IF_NAMESIZE);

        snprintf(pPcapIf->description, DPDKPCAP_IF_NAMESIZE, "DPDK interface");

        printf("Allocating memory for %s\n", pPcapIf->name);
    }

    pPcapPrevious->next = NULL;

    return DPDKPCAP_OK;
}

void pcap_freealldevs(pcap_if_t *alldevs)
{
    pcap_if_t *device = NULL;
    pcap_if_t *nextDevice = NULL;

    if (initFinished == 0)
    {
        return;
    }

    for(device = alldevs; device != NULL; device = nextDevice)
    {
        debug("Releasing memory for %s\n", device->name);
        free(device->name);
        free(device->description);

        nextDevice = device->next;
        free(device);
    }
}

int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)
{
    int ret = 0;
    struct rte_mbuf* mbuf = NULL;

    if (p == NULL || buf == NULL ||
        p->deviceId < 0 || p->deviceId > RTE_MAX_ETHPORTS)
    {
        snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Invalid parameter");
        return DPDKPCAP_FAILURE;
    }

    mbuf = rte_pktmbuf_alloc(txPool);
    if (mbuf == NULL)
    {
        snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Could not allocate buffer on port %d\n", p->deviceId);
        return DPDKPCAP_FAILURE;
    }

    if (mbuf->buf_len < size)
    {
        snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Can not copy packet data : packet size %d, mbuf length %d, port %d\n",
               size, mbuf->buf_len, p->deviceId);
        return DPDKPCAP_FAILURE;
    }

    rte_memcpy(mbuf->pkt.data, buf, size);
    mbuf->pkt.data_len = size;
    mbuf->pkt.pkt_len = size;
    mbuf->pkt.nb_segs = 1;

    ret = rte_eth_tx_burst(p->deviceId, 0, &mbuf, 1);
    if (ret < 1)
    {
        snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Could not send a packet on port %d\n", p->deviceId);
        rte_pktmbuf_free(mbuf);
        return DPDKPCAP_FAILURE;
    }

    debug("Sent a packet to port %d\n", p->deviceId);

    return DPDKPCAP_OK;
}

pcap_dumper_t * pcap_dump_open(pcap_t *p, const char *fname)
{
    return NULL;
}

int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
    const u_char **pkt_data)
{
    struct rte_mbuf* mbuf = NULL;
    int              len  = 0;

    if (p == NULL || pkt_header == NULL || pkt_data == NULL ||
        p->deviceId < 0 || p->deviceId > RTE_MAX_ETHPORTS)
    {
        snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Invalid parameter");
        return DPDKPCAP_FAILURE;
    }

    debug("Receiving a packet on port %d\n", p->deviceId);

    while (!rte_eth_rx_burst(p->deviceId, 0, &mbuf, 1))
    {
    }

    len = rte_pktmbuf_pkt_len(mbuf);

    pktHeader_g.len = len;
    *pkt_header = &pktHeader_g;

    rte_memcpy((void*)data_g, rte_pktmbuf_mtod(mbuf, void*), len);
    *pkt_data = data_g;

    rte_pktmbuf_free(mbuf);

    return 1;
}

void pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
}

char* pcap_geterr(pcap_t *p)
{
    return errbuf_g;
}

void pcap_dump_close(pcap_dumper_t *p)
{
}

int pcap_setdirection(pcap_t *p, pcap_direction_t d)
{
    return DPDKPCAP_OK;
}

void pcap_breakloop(pcap_t *p)
{
}

const char *pcap_lib_version(void)
{
    return pcap_version_string;
}

int pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf)
{
    return DPDKPCAP_OK;
}

int pcap_getnonblock(pcap_t *p, char *errbuf)
{
    return DPDKPCAP_OK;
}

int pcap_fileno(pcap_t *p)
{
    return DPDKPCAP_OK;
}

int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
{
    return DPDKPCAP_OK;
}

const u_char* pcap_next(pcap_t *p, struct pcap_pkthdr *h)
{
    return NULL;
}

int pcap_is_swapped(pcap_t *p)
{
    return 0;
}

int pcap_stats(pcap_t *p, struct pcap_stat *ps)
{
    return DPDKPCAP_OK;
}

pcap_t* pcap_open_dead(int linktype, int snaplen)
{
    return NULL;
}

pcap_t* pcap_open_offline(const char *fname, char *errbuf)
{
    return NULL;
}

FILE* pcap_file(pcap_t *p)
{
    return NULL;
}

int pcap_major_version(pcap_t *p)
{
    return 0;
}

int pcap_minor_version(pcap_t *p)
{
    return 0;
}

int
pcap_compile(pcap_t *p, struct bpf_program *program,
         const char *buf, int optimize, bpf_u_int32 mask)
{
    return DPDKPCAP_OK;
}

int
pcap_snapshot(pcap_t *p)
{
    return DPDKPCAP_OK;
}

int
pcap_datalink(pcap_t *p)
{
    return DPDKPCAP_OK;
}

int pcap_lookupnet (const char *device, bpf_u_int32 *localnet,
                    bpf_u_int32 *netmask, char *errbuf)
{
    return DPDKPCAP_OK;
}

int
pcap_list_datalinks(pcap_t *p, int **dlt_buffer)
{
    return DPDKPCAP_OK;
}

static int txLoop(void* arg)
{
    int ret = 0;
    dpdkpcap_tx_args_t* args_p = (dpdkpcap_tx_args_t*)arg;
    int number = args_p->number;
    int portId = args_p->portId;

    int lcoreId = rte_lcore_id();
    int packets = 0;
    int i = 0;

    debug("Starting transmit: core %u, port %u, packets num %d\n", lcoreId, portId, number);

    while (1)
    {
        for (i = 0; i < DEF_PKT_BURST; i++)
        {
            rte_pktmbuf_refcnt_update(mbuf_g[i], 1);
        }

        ret = rte_eth_tx_burst(portId, 0, mbuf_g, DEF_PKT_BURST);
        if (ret < DEF_PKT_BURST)
        {
            snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Could not send a packet on port %d\n", portId);
            for (i = DEF_PKT_BURST - ret; i < DEF_PKT_BURST; i++)
            {
                rte_pktmbuf_free(mbuf_g[i]);
            }

            debug("Transmitted %u packets\n", packets);

            return DPDKPCAP_FAILURE;
        }

        packets += DEF_PKT_BURST;

        if (args_p->number > 0)
        {
            if (number < 1)
                break;

            number -= DEF_PKT_BURST;
        }
    }

    debug("Finished transmit on core %u\n", lcoreId);

    return DPDKPCAP_OK;
}

int dpdpcap_transmit_in_loop(pcap_t *p, const u_char *buf, int size, int number)
{
    int transmitLcoreId = 0;
    int i = 0;

    if (p == NULL || buf == NULL ||
        p->deviceId < 0 || p->deviceId > RTE_MAX_ETHPORTS)
    {
        snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Invalid parameter");
        return DPDKPCAP_FAILURE;
    }

    for (i = 0; i < DEF_PKT_BURST; i++)
    {
        mbuf_g[i] = rte_pktmbuf_alloc(txPool);
        if (mbuf_g[i] == NULL)
        {
            snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Could not allocate buffer on port %d\n", p->deviceId);
            return DPDKPCAP_FAILURE;
        }

        struct rte_mbuf* mbuf = mbuf_g[i];

        if (mbuf->buf_len < size)
        {
            snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Can not copy packet data : packet size %d, mbuf length %d, port %d\n",
                   size, mbuf->buf_len, p->deviceId);
            return DPDKPCAP_FAILURE;
        }

        rte_memcpy(mbuf->pkt.data, buf, size);
        mbuf->pkt.data_len = size;
        mbuf->pkt.pkt_len = size;
        mbuf->pkt.nb_segs = 1;
    }

    dpdkpcap_tx_args_t args;
    args.number = number;
    args.portId = p->deviceId;
    transmitLcoreId = p->deviceId + 1;

    debug("Transferring TX loop to the core %u\n", transmitLcoreId);

    if (rte_eal_remote_launch(txLoop, &args, transmitLcoreId) < 0)
    {
        snprintf (errbuf_g, PCAP_ERRBUF_SIZE, "Can not run TX on a slave core: transmitLcoreId %d\n",
                  transmitLcoreId);
        return DPDKPCAP_FAILURE;
    }

    rte_eal_wait_lcore(transmitLcoreId);

    return DPDKPCAP_OK;
}

