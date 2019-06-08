#ifndef _NSS_PUP_H
#define _NSS_PUP_H

#include <pcap/pcap.h>

void nss_callback_print_pup(const struct pcap_pkthdr* pk, const u_char* packet);

#endif /* _NSS_PUP_H */