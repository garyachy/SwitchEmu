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

    DPDKPCAP_TX_PTHRESH 				= 36,	/**< Default values of TX prefetch threshold reg. */
    DPDKPCAP_TX_HTHRESH 				= 0,	/**< Default values of TX host threshold reg. */
    DPDKPCAP_TX_WTHRESH 				= 0,	/**< Default values of TX write-back threshold reg. */
    DPDKPCAP_TX_WTHRESH_1GB             = 16	/**< Default value for 1GB ports */
};

void startRxLoop();
void stopRxLoop();
int isRxLoopStarted();
int rxLoop(void* arg);

#endif // COMMON_H
