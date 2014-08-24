#include <stdio.h>
#include <pcap.h>

#define PACKET_SIZE 100

void my_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char*packet)
{
   printf("Received a packet of length %d \n", pkthdr->len);
}

int main(int argc, char *argv[])
{
    pcap_t *handles[2];
    pcap_pkthdr *header = NULL;
    const u_char *pktdata = NULL;

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t *deviceList;
    pcap_if_t *device;

    u_char packet[PACKET_SIZE];
    int i = 0;
    int sendFlag  = 1;

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

    for (i = 0; i < 10; i++)
    {
        /*printf("Sending a packet %d\n", i + 1);

        if (pcap_sendpacket(handles[0], packet, sizeof(packet)) < 0)
        {
            printf("pcap_sendpacket failed\n");
            return -1;
        }*/

        printf("Receiving a packet %d\n", i + 1);

        if (pcap_next_ex(handles[0], &header, &pktdata) < 0)
        {
            printf("pcap_next_ex failed\n");
            continue;
        }
        //pcap_loop(handle, -1, my_callback, NULL);
        printf("Received a buffer of length %d\n", header->len);
    }

    for(i = 0; i < 2; i++)
    {
        pcap_close(handles[i]);
    }

    pcap_freealldevs(deviceList);

    return(0);
}
