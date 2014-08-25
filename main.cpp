#include <stdio.h>
#include <pcap.h>

#define PACKET_SIZE 100

#define TX_HANDLE 3
#define RX_HANDLE 4
#define HANDLE_NUM 10
#define REPEAT_NUM 10

void my_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char*packet)
{
   printf("Received a packet of length %d \n", pkthdr->len);
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

    createPacket(packet);

    printf("Retrieving the device list from the local machine\n");

    if(pcap_findalldevs(&deviceList, errbuf) < 0)
    {
        printf("Error in pcap_findalldevs_ex: %s\n", errbuf);
        return -1;
    }

    i = 0;

    for(device = deviceList; device != NULL; device = device->next)
    {
        printf("%s\n", device->name);

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
        printf("Sending a packet %d\n", i + 1);

        if (pcap_sendpacket(handles[TX_HANDLE], packet, sizeof(packet)) < 0)
        {
            printf("pcap_sendpacket failed\n");
            return -1;
        }

        printf("Receiving a packet %d\n", i + 1);

        if (pcap_next_ex(handles[RX_HANDLE], &header, &pktdata) < 0)
        {
            printf("pcap_next_ex failed\n");
            continue;
        }

        printf("Received a buffer of length %d\n", header->len);
    }

    for(i = 0; i < 2; i++)
    {
        pcap_close(handles[i]);
    }

    pcap_freealldevs(deviceList);

    return 0;
}

int test2()
{
    pcap_t *handles[HANDLE_NUM];
    pcap_pkthdr *header = NULL;
    const u_char *pktdata = NULL;

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t *deviceList;
    pcap_if_t *device;

    u_char packet[PACKET_SIZE];
    int i = 0;

    createPacket(packet);

    printf("Retrieving the device list from the local machine\n");

    if(pcap_findalldevs(&deviceList, errbuf) < 0)
    {
        printf("Error in pcap_findalldevs_ex: %s\n", errbuf);
        return -1;
    }

    i = 0;

    for(device = deviceList; device != NULL; device = device->next)
    {
        printf("%s\n", device->name);

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
        printf("Sending a packet %d\n", i + 1);

        if (pcap_sendpacket(handles[TX_HANDLE], packet, sizeof(packet)) < 0)
        {
            printf("pcap_sendpacket failed\n");
            return -1;
        }

        printf("Receiving a packet %d\n", i + 1);

        if (pcap_loop(handles[RX_HANDLE], 1, my_callback, NULL) < 0)
        {
            printf("pcap_loop failed\n");
            continue;
        }
    }

    for(i = 0; i < 2; i++)
    {
        pcap_close(handles[i]);
    }

    pcap_freealldevs(deviceList);

    return 0;
}

int main(int argc, char *argv[])
{
    (test1() == 0) ? printf("Test 1 - OK\n") : printf("Test 1 - FAILED\n");
    (test2() == 0) ? printf("Test 2 - OK\n") : printf("Test 2 - FAILED\n");

    return(0);
}
