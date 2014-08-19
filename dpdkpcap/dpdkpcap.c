#include <pcap.h>

pcap_t* pcap_open_live(const char *source, int snaplen, int promisc, int to_ms, char *errbuf)
{
    pcap_t *p = NULL;

    return p;
}

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
    return -1;
}

void pcap_close(pcap_t *p)
{
}

int pcap_findalldevs (pcap_if_t **alldevsp, char *errbuf)
{
    return -1;
}

void pcap_freealldevs(pcap_if_t *alldevs)
{
}

int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)
{
    return -1;
}

pcap_dumper_t * pcap_dump_open(pcap_t *p, const char *fname)
{
    return NULL;
}

int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
    const u_char **pkt_data)
{
    return -1;
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
    return -1;
}

void pcap_breakloop(pcap_t *p)
{
}
