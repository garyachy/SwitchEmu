#include <stdio.h>
#include <pcap.h>

void my_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char*packet)
{
   printf("Received a packet of length %d \n", pkthdr->len);
}

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t *deviceList;
    pcap_if_t *device;

    printf("Retrieving the device list from the local machine\n");

    if(pcap_findalldevs(&deviceList, errbuf) == -1)
    {
        printf("Error in pcap_findalldevs_ex: %s\n", errbuf);
        return -1;
    }

    for(device = deviceList; device != NULL; device = device->next)
    {
        printf("%s", device->name);
        if (device->description)
            printf(" : (%s)\n", device->description);
        else
            printf("\n");
    }

    pcap_freealldevs(deviceList);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    printf("Opened device: %s\n", dev);

    pcap_loop(handle, -1, my_callback, NULL);

    pcap_close(handle);

    return(0);
}
