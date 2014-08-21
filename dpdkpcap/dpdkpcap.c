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

#define DPDKPCAP_MBUF_SIZE       (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define DPDKPCAP_NB_MBUF         512
#define DPDKPCAP_CACHE_SIZE      32
#define DPDKPCAP_RX_QUEUE_NUMBER 1
#define DPDKPCAP_TX_QUEUE_NUMBER 1
#define DPDKPCAP_IF_NAMESIZE     16

int initFinished = 0;
int portInitFinished[RTE_MAX_ETHPORTS] = {0};
rte_atomic16_t startRx = RTE_ATOMIC16_INIT(0);

struct rte_mempool* rxPool = 0;
#define DPDKPCAP_RX_POOL_NAME "RX_POOL"
#define DPDKPCAP_RX_QUEUE_DESC_NUMBER DPDKPCAP_NB_MBUF

struct rte_mempool* txPool = 0;
#define DPDKPCAP_TX_POOL_NAME "TX_POOL"
#define DPDKPCAP_TX_QUEUE_DESC_NUMBER DPDKPCAP_NB_MBUF

DpdkPcapResultCode_t globalInit()
{
    char *args[] = {"dpdkpcap_test", "-c0x03", "-n2", "-m128", "--file-prefix=dpdkpcap_test"};

    if (initFinished == 1)
    {
        return DPDKPCAP_OK;
    }

    if (rte_eal_init(sizeof(args)/sizeof(char*), args) < 0)
    {
        return DPDKPCAP_FAILURE;
    }

//#if RTE_VER_MAJOR == 1
//#if RTE_VER_MINOR < 7
    if (rte_pmd_init_all() < 0)
    {
        return DPDKPCAP_FAILURE;
    }
//#endif
//#endif
    if (rte_eal_pci_probe() < 0)
    {
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
        return DPDKPCAP_FAILURE;
    }

    rte_eal_mp_remote_launch(rxLoop, NULL, SKIP_MASTER);

    startRxLoop();

    initFinished = 1;
    return DPDKPCAP_OK;
}

DpdkPcapResultCode_t deviceInit(int deviceId)
{
    struct rte_eth_conf portConf;
    struct rte_eth_rxconf rxConf;
    struct rte_eth_txconf txConf;
    int queueId = 0;
    int ret = 0;

    memset(&portConf, 0, sizeof(portConf));
    memset(&rxConf, 0, sizeof(rxConf));
    memset(&txConf, 0, sizeof(txConf));

    if (initFinished == 0)
    {
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
        printf ("Could not configure the device %d", deviceId);
        return DPDKPCAP_FAILURE;
    }

    rxConf.rx_thresh.pthresh = DPDKPCAP_RX_PTHRESH;
    rxConf.rx_thresh.hthresh = DPDKPCAP_RX_HTHRESH;
    rxConf.rx_thresh.wthresh = DPDKPCAP_RX_WTHRESH;

    if (rte_eth_rx_queue_setup(deviceId, queueId, DPDKPCAP_RX_QUEUE_DESC_NUMBER, SOCKET_ID_ANY, &rxConf, rxPool) < 0)
    {
        printf ("Could not setup RX queue of the device %d", deviceId);
        return DPDKPCAP_FAILURE;
    }

    txConf.tx_thresh.pthresh = DPDKPCAP_TX_PTHRESH;
    txConf.tx_thresh.hthresh = DPDKPCAP_TX_HTHRESH;
    txConf.tx_thresh.wthresh = DPDKPCAP_TX_WTHRESH;

    if (rte_eth_tx_queue_setup(deviceId, queueId, DPDKPCAP_TX_QUEUE_DESC_NUMBER, SOCKET_ID_ANY, &txConf) < 0)
    {
        printf ("Could not setup TX queue of the device %d", deviceId);
        return DPDKPCAP_FAILURE;
    }

    ret = rte_eth_dev_start(deviceId);
    if (ret < 0)
    {
        printf ("Could not start the device %d, err %d", deviceId, ret);
        return DPDKPCAP_FAILURE;
    }

    rte_eth_promiscuous_enable(deviceId);

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

pcap_t* pcap_open_live(const char *source, int snaplen, int promisc, int to_ms, char *errbuf)
{
    pcap_t *p = NULL;

    if (initFinished == 0)
    {
        return NULL;
    }

    return p;
}

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
    if (initFinished == 0)
    {
        return DPDKPCAP_FAILURE;
    }

    return DPDKPCAP_FAILURE;
}

void pcap_close(pcap_t *p)
{
}

int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
{
    int       port     = 0;
    pcap_if_t *pPcapIf = NULL;
    struct rte_eth_dev_info info;

    if (globalInit() != DPDKPCAP_OK)
    {
        snprintf (errbuf, PCAP_ERRBUF_SIZE, "Could not initialize DPDK");
        return DPDKPCAP_FAILURE;
    }

    int portsNumber = rte_eth_dev_count();
    if (portsNumber < 1)
    {
        return DPDKPCAP_FAILURE;
    }

    printf ("Discovered %d devices", portsNumber);

    pPcapIf = *alldevsp;

    for (port = 0; port < portsNumber; port++, pPcapIf = pPcapIf->next)
    {
        if (deviceInit(port) == DPDKPCAP_FAILURE)
        {
            snprintf (errbuf, PCAP_ERRBUF_SIZE, "Could not initialize the port %d", port);
            return DPDKPCAP_FAILURE;
        }

        pPcapIf = malloc(sizeof(pcap_if_t));

        rte_eth_dev_info_get(port, &info);

        pPcapIf->name = malloc(DPDKPCAP_IF_NAMESIZE);
        snprintf(pPcapIf->name, DPDKPCAP_IF_NAMESIZE, "enp%us%u",
                 info.pci_dev->addr.bus,
                 info.pci_dev->addr.devid);
    }

    return DPDKPCAP_OK;
}

void pcap_freealldevs(pcap_if_t *alldevs)
{
    int port = 0;
    int portsNumber = rte_eth_dev_count();

    if (initFinished == 0)
    {
        return;
    }

    if (portsNumber < 1)
    {
        return;
    }

    for (port = 0; port < portsNumber; port++)
    {
        deviceDeInit(port);
    }
}

int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)
{
    return DPDKPCAP_FAILURE;
}

pcap_dumper_t * pcap_dump_open(pcap_t *p, const char *fname)
{
    return NULL;
}

int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
    const u_char **pkt_data)
{
    return DPDKPCAP_FAILURE;
}

void pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
}

char* pcap_geterr(pcap_t *p)
{
    return NULL;
}

void pcap_dump_close(pcap_dumper_t *p)
{
}

int pcap_setdirection(pcap_t *p, pcap_direction_t d)
{
    return DPDKPCAP_FAILURE;
}

void pcap_breakloop(pcap_t *p)
{
}

DpdkPcapResultCode_t sendPacket(int deviceId, const u_char *buf, int size)
{
    struct rte_mbuf *mbuf = NULL;

    if (initFinished == 0)
    {
        return DPDKPCAP_FAILURE;
    }

    mbuf = rte_pktmbuf_alloc(rxPool);

    rte_memcpy(rte_pktmbuf_mtod(mbuf, char*), buf, size);

    rte_eth_tx_burst(deviceId, 0, &mbuf, size);

    return DPDKPCAP_FAILURE;
}

void startRxLoop()
{
    rte_atomic16_set(&startRx, 1);
}

void stopRxLoop()
{
    rte_atomic16_set(&startRx, 0);
}

int isRxLoopStarted()
{
    return (rte_atomic16_read(&startRx) == 1);
}

int rxLoop(void* arg)
{
    while(isRxLoopStarted())
    {
    }
}
