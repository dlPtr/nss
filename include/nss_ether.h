#ifndef _NSS_ETHERNET_H
#define _NSS_ETHERNET_H

#include <arpa/inet.h>
#include <pcap/pcap.h>

struct Nss_ether {
    u_char dstHost[6];  /* Destination host address */
    u_char srcHost[6];  /* Source host address */
    u_short type; /* IP, ARP, RARP, PUP */
};
typedef struct Nss_ether nss_ether_t;

#endif /* _NSS_ETHERNET_H */
