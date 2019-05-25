#include <assert.h>
#include <pcap/pcap.h>
#include <stdio.h>

void svPkt(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char* argv[])
{
    char errBuf[PCAP_ERRBUF_SIZE];

    /* 1. Find available interfaces */
    pcap_if_t* pAllDev = NULL;
    assert(0 == pcap_findalldevs(&pAllDev, errBuf));
    if (pAllDev)
        printf("Select interface: %s\n", pAllDev->name);
    else
        perror("No available interface");

    /* 2. Create handle */
    pcap_t* handle = NULL;
    assert(handle = pcap_create(pAllDev->name, errBuf));
    pcap_freealldevs(pAllDev);

    /* 3. Set appropriate options and Activate */
    assert(0 == pcap_set_promisc(handle, 0));
    assert(0 == pcap_set_snaplen(handle, 65535));
    assert(0 == pcap_activate(handle));

    /* 4. Set filter */
    struct bpf_program filter;
    assert(0 == pcap_compile(handle, &filter, "ip", 1, 0));
    assert(0 == pcap_setfilter(handle, &filter));

    /* 5. Captrue packets */
    pcap_dumper_t* dumper;
    assert(dumper = pcap_dump_open(handle, "cap.pcap"));
    pcap_loop(handle, -1, svPkt, (u_char*)dumper);

    /* 6. Close handle */
    pcap_close(handle);

    return 0;
}

void svPkt(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    pcap_dump(arg, pkthdr, packet);
    pcap_dump_flush((pcap_dumper_t*)arg);
}
