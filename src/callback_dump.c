#include <assert.h>
#include "callback.h"
#include "log.h"

void nss_callback_svPkt(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    assert(arg);
    assert(pkthdr);
    assert(packet);

    pcap_dump(arg, pkthdr, packet);
    if(pcap_dump_flush((pcap_dumper_t*)arg))
        nss_print_err("dump flush error detected!");
}

int nss_callback_dump(pcap_t* handle, const char* fileName, int count)
{
    assert(handle);
    assert(fileName);
    assert(count >= 0);

    pcap_dumper_t* dumper;
    dumper = pcap_dump_open(handle, fileName);
    if (!dumper) {
        nss_print_err("dump open file failed!");
        return NSS_FAILED;
    }

    if (PCAP_ERROR == pcap_loop(handle,\
        (count == 0 ? -1 : count), nss_callback_svPkt, (u_char*)dumper)) {
        nss_print_err("Captrue loop error detected\n");
        return NSS_FAILED;
    }
        
    return NSS_SUCCESS;
}