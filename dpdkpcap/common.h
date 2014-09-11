#ifndef COMMON_H
#define COMMON_H

typedef enum
{
    DPDKPCAP_FAILURE = -1,
    DPDKPCAP_OK = 0
} DpdkPcapResultCode_t;

enum {
    DPDKPCAP_RX_PTHRESH 				= 8,	/**< Default values of RX prefetch threshold reg. */
    DPDKPCAP_RX_HTHRESH 				= 8,	/**< Default values of RX host threshold reg. */
    DPDKPCAP_RX_WTHRESH 				= 4,	/**< Default values of RX write-back threshold reg. */

    DPDKPCAP_TX_PTHRESH 				= 32,	/**< Default values of TX prefetch threshold reg. */
    DPDKPCAP_TX_HTHRESH 				= 0,	/**< Default values of TX host threshold reg. */
    DPDKPCAP_TX_WTHRESH 				= 0,	/**< Default values of TX write-back threshold reg. */
    DPDKPCAP_TX_WTHRESH_1GB             = 16	/**< Default value for 1GB ports */
};

struct pcap
{
    int deviceId;
};

typedef struct dpdkpcap_tx_args_s
{
    int portId;
    int number;
} dpdkpcap_tx_args_t;

#ifdef __cplusplus
extern "C" {
#endif

int linkStatusGet(const char* device);
int rxStatsGet(pcap_t *p);
int txStatsGet(pcap_t *p);

int dpdpcap_transmit_in_loop(pcap_t *p, const u_char *buf, int size, int number);

#ifdef __cplusplus
}
#endif

#endif // COMMON_H
