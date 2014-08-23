#include <stdio.h>
#include <pcap.h>

void my_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char*packet)
{
   printf("Received a packet of length %d \n", pkthdr->len);
}

int main(int argc, char *argv[])
{
    pcap_t *handle = NULL;
    pcap_pkthdr *header = NULL;
    const u_char *pktdata = NULL;

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t *deviceList;
    pcap_if_t *device;

    u_char packet[100];
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

    for(i=12;i<100;i++){
       packet[i]=i%256;
    }

    printf("Retrieving the device list from the local machine\n");

    if(pcap_findalldevs(&deviceList, errbuf) < 0)
    {
        printf("Error in pcap_findalldevs_ex: %s\n", errbuf);
        return -1;
    }

    for(device = deviceList; device != NULL; device = device->next)
    {
        printf("%s\n", device->name);

        handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL)
        {
            printf("Couldn't open device %s: %s\n", device->name, errbuf);
            return -1;
        }

        if (sendFlag)
        {
            if (pcap_sendpacket(handle, packet, sizeof(packet)) < 0)
            {
                printf("pcap_sendpacket failed");
                return -1;
            }
            sendFlag = 0;
        }
        else
        {
            /*if (pcap_next_ex(handle, &header, &pktdata) < 0)
            {
                printf("pcap_next_ex failed");
                return -1;
            }*/
            pcap_loop(handle, 10, my_callback, NULL);
            //printf("Received a buffer %s\n", pktdata);
        }

        pcap_close(handle);
    }

    pcap_freealldevs(deviceList);

    return(0);
}
