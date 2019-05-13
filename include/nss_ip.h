#ifndef _NSS_IP_H
#define _NSS_IP_H

#include <pcap/pcap.h>

struct Nss_ip {
    u_char ip_vhl;		/* version:4 | header length:4 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	u_int ip_src,ip_dst; /* source and dest address */
};
typedef struct Nss_ip nss_ip_t;

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

void nss_callback_print_ip(const struct pcap_pkthdr* pk, const u_char* packet);
const char* nss_ip_getInfo(const nss_ip_t* ip);

#endif /* _NSS_IP_H */