#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <stdlib.h>

#include "common.h"

//#define DEBUG

#ifdef DEBUG
#define debug printf
#else
#define debug
#endif

#define PACKET_SIZE 100

#define PORT_0 0
#define PORT_1 1
#define PORT_2 2

#define HANDLE_NUM 10
unsigned long long repeat_num_g = 10000;

time_t start, end;

void start_timer()
{
    time (&start);
}

void stop_timer()
{
    time (&end);
}

void print_rates(unsigned long long pktCount, unsigned long long pktSize)
{
    double diff = difftime (end, start);
    unsigned long long byteCount = pktCount * pktSize * 8;
    printf ("Sent/received %llu packets or %llu bytes per %.2lf seconds\n", pktCount, byteCount, diff);
    printf ("Rate is %.2lf pps or %.2lf bps\n", pktCount/diff, byteCount/diff);
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

    for (i = 0; i < repeat_num_g; i++)
    {
        debug("Sending a packet %d\n", i + 1);

        if (pcap_sendpacket(handles[PORT_0], packet, sizeof(packet)) < 0)
        {
            printf("pcap_sendpacket failed : %s\n", pcap_geterr(handles[PORT_0]));
            return -1;
        }

    /*    debug("Receiving a packet %d\n", i + 1);

        if (pcap_next_ex(handles[RX_HANDLE], &header, &pktdata) < 0)
        {
            printf("pcap_next_ex failed : %s\n", pcap_geterr(handles[RX_HANDLE]));
            continue;
        }

        debug("Received a buffer of length %d\n", header->len);*/
    }

    stop_timer();
    print_rates(repeat_num_g, PACKET_SIZE);

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

    for (i = 0; i < repeat_num_g; i++)
    {
        debug("Sending a packet %d\n", i + 1);

        if (pcap_sendpacket(handles[PORT_0], packet, sizeof(packet)) < 0)
        {
            printf("pcap_sendpacket failed : %s\n", pcap_geterr(handles[PORT_0]));
            return -1;
        }

        debug("Receiving a packet %d\n", i + 1);

        if (pcap_loop(handles[PORT_1], 1, my_callback, NULL) < 0)
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
    char *deviceName = NULL;
    pcap_t *handle = NULL;
    u_char packet[PACKET_SIZE];

    int packets_number = repeat_num_g;

    createPacket(packet);

    if ( (deviceName = pcap_lookupdev(errbuf)) == NULL)
    {
        return -1;
    }

    handle = pcap_open_live(deviceName, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        printf("Couldn't open device %s: %s\n", deviceName, errbuf);
        return -1;
    }

    printf("Sending %u packets\n", packets_number);

    start_timer();

    if (dpdpcap_transmit_in_loop(handle, packet, sizeof(packet), packets_number) < 0)
    {
        printf("dpdpcap_transmit_in_loop failed : %s\n", pcap_geterr(handle));
        return -1;
    }

    stop_timer();
    print_rates(packets_number, PACKET_SIZE);

    pcap_close(handle);

    return 0;
}

int test4()
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

    for (i = 0; i < repeat_num_g; i++)
    {
        debug("Sending a packet %d\n to %d port", i + 1, PORT_0);

        if (pcap_sendpacket(handles[PORT_0], packet, sizeof(packet)) < 0)
        {
            printf("pcap_sendpacket failed : %s\n", pcap_geterr(handles[PORT_0]));
            return -1;
        }

        debug("Sending a packet %d\n to %d port", i + 1, PORT_1);

        if (pcap_sendpacket(handles[PORT_1], packet, sizeof(packet)) < 0)
        {
            printf("pcap_sendpacket failed : %s\n", pcap_geterr(handles[PORT_1]));
            return -1;
        }
    }

    stop_timer();
    print_rates(repeat_num_g, PACKET_SIZE);

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

int main(int argc, char *argv[])
{
    if (argc > 1)
    {
        repeat_num_g = atol(argv[1]);
    }

    (test1() == 0) ? printf("Test 1 - OK\n") : printf("Test 1 - FAILED\n");
    //(test2() == 0) ? printf("Test 2 - OK\n") : printf("Test 2 - FAILED\n");
    //(test3() == 0) ? printf("Test 3 - OK\n") : printf("Test 3 - FAILED\n");
    (test4() == 0) ? printf("Test 4 - OK\n") : printf("Test 4 - FAILED\n");

    return(0);
}
