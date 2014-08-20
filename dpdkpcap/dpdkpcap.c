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

struct rte_mempool* rxPool = 0;
#define DPDKPCAP_RX_POOL_NAME "RX_POOL"
#define DPDKPCAP_RX_QUEUE_DESC_NUMBER DPDKPCAP_NB_MBUF

struct rte_mempool* txPool = 0;
#define DPDKPCAP_TX_POOL_NAME "TX_POOL"
#define DPDKPCAP_TX_QUEUE_DESC_NUMBER DPDKPCAP_NB_MBUF

DpdkPcapResultCode_t globalInit()
{
    char  arg0[] = "program";
    char  arg1[] = "-c";
    char  arg2[] = "0x03";
    char  arg3[] = "-n";
    char  arg4[] = "2";
    char* argv[] = { &arg0[0], &arg1[0], &arg2[0], &arg3[0], &arg4[0], NULL };
    int   argc   = (int)(sizeof(argv) / sizeof(argv[0])) - 1;

    if (initFinished == 1)
    {
        return DPDKPCAP_OK;
    }

    if (rte_eal_init(argc, argv) < 0)
    {
        return DPDKPCAP_FAILURE;
    }

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

    printf ("Global init succedded");

    initFinished = 1;
    return DPDKPCAP_OK;
}

DpdkPcapResultCode_t deviceInit(int deviceId)
{
    struct rte_eth_conf portConf;
    struct rte_eth_rxconf rxConf;
    struct rte_eth_txconf txConf;
    int queueId = 0;
    int ret;

    memset(&portConf, 0, sizeof(portConf));
    memset(&rxConf, 0, sizeof(rxConf));
    memset(&txConf, 0, sizeof(txConf));

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

    if (ret = rte_eth_dev_configure(deviceId, DPDKPCAP_RX_QUEUE_NUMBER, DPDKPCAP_TX_QUEUE_NUMBER, &portConf) < 1)
    {
        printf ("Could not configure the device %d, err %d", deviceId, ret);
        return DPDKPCAP_FAILURE;
    }

    rxConf.rx_thresh.pthresh = 8;
    rxConf.rx_thresh.hthresh = 8;
    rxConf.rx_thresh.wthresh = 4;

    if (rte_eth_rx_queue_setup(deviceId, queueId, DPDKPCAP_RX_QUEUE_DESC_NUMBER, SOCKET_ID_ANY, &rxConf, rxPool) < 0)
    {
        printf ("Could not setup RX queue of the device %d", deviceId);
        return DPDKPCAP_FAILURE;
    }

    txConf.tx_thresh.pthresh = 16;
    txConf.tx_thresh.hthresh = 0;
    txConf.tx_thresh.wthresh = 0;

    if (rte_eth_tx_queue_setup(deviceId, queueId, DPDKPCAP_TX_QUEUE_DESC_NUMBER, SOCKET_ID_ANY, &txConf) < 0)
    {
        printf ("Could not setup TX queue of the device %d", deviceId);
        return DPDKPCAP_FAILURE;
    }

    if (rte_eth_dev_start(deviceId) < 0)
    {
        printf ("Could not start the device %d", deviceId);
        return DPDKPCAP_FAILURE;
    }

    portInitFinished[deviceId] = 1;

    return DPDKPCAP_OK;
}

pcap_t* pcap_open_live(const char *source, int snaplen, int promisc, int to_ms, char *errbuf)
{
    pcap_t *p = NULL;

    return p;
}

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
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

    globalInit();

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
            printf ("Could not initialize the port %d", port);
            return DPDKPCAP_FAILURE;
        }

        pPcapIf = malloc(sizeof(pcap_if_t));

        rte_eth_dev_info_get(port, &info);

        pPcapIf->name = malloc(DPDKPCAP_IF_NAMESIZE);
        snprintf(pPcapIf->name, DPDKPCAP_IF_NAMESIZE, "enp%us%u",
                 info.pci_dev->addr.bus,
                 info.pci_dev->addr.devid);
    }

    return DPDKPCAP_FAILURE;
}

void pcap_freealldevs(pcap_if_t *alldevs)
{
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
