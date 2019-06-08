#ifndef _NSS_RARP_H
#define _NSS_RARP_H

#include "nss_arp.h"

void nss_callback_print_rarp(const struct pcap_pkthdr* pk, const u_char* packet);
const char* nss_rarp_getInfo(const nss_arp_t* pArp);

#endif /* _NSS_ARP_H */