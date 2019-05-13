#include <assert.h>
#include <pcap/pcap.h>
#include <stdio.h>

void svPkt(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char* argv[])
{
    char errBuf[PCAP_ERRBUF_SIZE];

    /* 1. Read from file */
    pcap_t* handle = pcap_open_offline("test.pcap", errBuf);
    assert(handle);

    /* 5. Captrue packets */
    assert(!pcap_loop(handle, -1, svPkt, "nihao"));

    pcap_breakloop(handle);

    /* 6. Close handle */
    pcap_close(handle);

    return 0;
}

void svPkt(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    puts("Catched");
}
