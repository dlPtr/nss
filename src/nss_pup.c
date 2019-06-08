#include "nss_pup.h"
#include <pcap/pcap.h>

void nss_callback_print_pup(const struct pcap_pkthdr* pk, const u_char* packet)
{
    puts("pup packet caught..");
}