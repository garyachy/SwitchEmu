#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include "common.h"

//#define DEBUG

#ifdef DEBUG
#define debug printf
#else
#define debug
#endif

#define PACKET_SIZE 100

#define TX_HANDLE 0
#define RX_HANDLE 1

#define HANDLE_NUM 10
#define REPEAT_NUM 10

time_t start, end;

void start_timer()
{
    time (&start);
}

void stop_timer()
{
    time (&end);
}

void print_rates(int pktCount, int pktSize)
{
    double diff = difftime (end, start);
    printf ("Sent/received %d packets of size %d per %.2lf seconds\n", pktCount, pktSize, diff);
    printf ("Rate is %.2lf pps or %.2lf bps\n", pktCount/diff, (pktCount * pktSize * 8)/diff);
}

void my_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char*packet)
{
   debug("Received a packet of length %d \n", pkthdr->len);
}

int createPacket(u_char* packet)
{
    int i = 0;

    packet[0]=1;
    packet[1]=1;
    packet[2]=1;
    packet[3]=1;
    packet[4]=1;
    packet[5]=1;

    packet[6]=2;
    packet[7]=2;
    packet[8]=2;
    packet[9]=2;
    packet[10]=2;
    packet[11]=2;

    packet[12]=0x88;
    packet[13]=0x80;

    for(i = 14; i < PACKET_SIZE; i++)
    {
       packet[i] = i%256;
    }
    return 0;
}

int test1()
{
    pcap_t *handles[HANDLE_NUM];
    pcap_pkthdr *header = NULL;
    const u_char *pktdata = NULL;

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t *deviceList;
    pcap_if_t *device;

    u_char packet[PACKET_SIZE];
    int i = 0;
    int status = 0;
    int rxPackets = 0;
    int txPackets = 0;

    memset(handles, 0, sizeof(handles));

    createPacket(packet);

    debug("Retrieving the device list from the local machine\n");

    if(pcap_findalldevs(&deviceList, errbuf) < 0)
    {
        printf("Error in pcap_findalldevs_ex: %s\n", errbuf);
        return -1;
    }

    i = 0;

    for(device = deviceList; device != NULL; device = device->next)
    {
        debug("%s\n", device->name);

        handles[i] = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
        if (handles[i] == NULL)
        {
            printf("Couldn't open device %s: %s\n", device->name, errbuf);
            return -1;
        }

        status = linkStatusGet(device->name);
        if (status)
            printf("Link is UP on device %s\n", device->name);
        else
            printf("Link is DOWN on device %s\n", device->name);

        i++;
    }

    start_timer();

    for (i = 0; i < REPEAT_NUM; i++)
    {
        debug("Sending a packet %d\n", i + 1);

        if (pcap_sendpacket(handles[TX_HANDLE], packet, sizeof(packet)) < 0)
        {
            printf("pcap_sendpacket failed : %s\n", pcap_geterr(handles[TX_HANDLE]));
            return -1;
        }

        debug("Receiving a packet %d\n", i + 1);

        if (pcap_next_ex(handles[RX_HANDLE], &header, &pktdata) < 0)
        {
            printf("pcap_next_ex failed : %s\n", pcap_geterr(handles[RX_HANDLE]));
            continue;
        }

        debug("Received a buffer of length %d\n", header->len);
    }

    stop_timer();
    print_rates(REPEAT_NUM, PACKET_SIZE);

    for(i = 0; i < HANDLE_NUM; i++)
    {
        if (handles[i] == 0)
            continue;

        rxPackets = rxStatsGet(handles[i]);
        if (rxPackets < 0)
            continue;

        txPackets = txStatsGet(handles[i]);
        if (txPackets < 0)
            continue;

        printf("%d : RX : %d, TX : %d \n", i, rxPackets, txPackets);

        pcap_close(handles[i]);
    }

    pcap_freealldevs(deviceList);

    return 0;
}

int test2()
{
    pcap_t *handles[HANDLE_NUM];

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t *deviceList;
    pcap_if_t *device;

    u_char packet[PACKET_SIZE];
    int i = 0;

    memset(handles, 0, sizeof(handles));

    createPacket(packet);

    debug("Retrieving the device list from the local machine\n");

    if(pcap_findalldevs(&deviceList, errbuf) < 0)
    {
        printf("Error in pcap_findalldevs_ex: %s\n", errbuf);
        return -1;
    }

    i = 0;

    for(device = deviceList; device != NULL; device = device->next)
    {
        debug("%s\n", device->name);

        handles[i] = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
        if (handles[i] == NULL)
        {
            printf("Couldn't open device %s: %s\n", device->name, errbuf);
            return -1;
        }

        i++;
    }

    for (i = 0; i < REPEAT_NUM; i++)
    {
        debug("Sending a packet %d\n", i + 1);

        if (pcap_sendpacket(handles[TX_HANDLE], packet, sizeof(packet)) < 0)
        {
            printf("pcap_sendpacket failed : %s\n", pcap_geterr(handles[TX_HANDLE]));
            return -1;
        }

        debug("Receiving a packet %d\n", i + 1);

        if (pcap_loop(handles[RX_HANDLE], 1, my_callback, NULL) < 0)
        {
            printf("pcap_loop failed\n");
            continue;
        }
    }

    for(i = 0; i < HANDLE_NUM; i++)
    {
        if (handles[i] == 0)
            continue;

        pcap_close(handles[i]);
    }

    pcap_freealldevs(deviceList);

    return 0;
}

int test3()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = NULL;

    if ( (device = pcap_lookupdev(errbuf)) == NULL)
    {
        return -1;
    }

    printf("Found a device %s\n", device);

    return 0;
}

int main(int argc, char *argv[])
{
    (test1() == 0) ? printf("Test 1 - OK\n") : printf("Test 1 - FAILED\n");
    (test2() == 0) ? printf("Test 2 - OK\n") : printf("Test 2 - FAILED\n");
    (test3() == 0) ? printf("Test 3 - OK\n") : printf("Test 3 - FAILED\n");

    return(0);
}
