#ifndef _NSS_ARP_H
#define _NSS_ARP_H

#include <pcap/pcap.h>

struct Nss_arp {
    u_short arp_hrd;    /* format of hardware address */
    u_short arp_pro;    /* format of protocol address */
    u_char arp_hln;    /* length of hardware address */
    u_char arp_pln;    /* length of protocol address */
    u_short arp_op;     /* ARP/RARP operation */

    u_char arp_sha[6];    /* sender hardware address */
    u_char arp_spa[4];        /* sender protocol address */
    u_char arp_tha[6];    /* target hardware address */
    u_char arp_tpa[4];        /* target protocol address */

    // /* nei cun dui qi */
    // u_char arp_sha[6];    /* sender hardware address */
    // u_int arp_spa;        /* sender protocol address */
    // u_char arp_tha[6];    /* target hardware address */
    // u_int arp_tpa;        /* target protocol address */
};
typedef struct Nss_arp nss_arp_t;

void nss_callback_print_arp(const struct pcap_pkthdr* pk, const u_char* packet);

/* Generate info */
const char* nss_arp_getInfo(const nss_arp_t* pArp);
void nss_arp_get_ip(const u_char* arr, char* ip);

/* Get arp type */
const char* nss_arp_get_type(int op);

#endif /* _NSS_ARP_H */