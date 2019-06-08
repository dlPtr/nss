#include <assert.h>
#include "utils.h"
#include "nss_ip.h"
#include "log.h"

void nss_callback_print_ip(const struct pcap_pkthdr* pk, const u_char* packet)
{
    assert(pk);
    assert(packet);

    nss_ip_t* pIp = (nss_ip_t*)(packet + 14);

    char ipSrc[12];
    char ipDst[12];
    nss_ip_ntoa(pIp->ip_src, ipSrc);
    nss_ip_ntoa(pIp->ip_dst, ipDst);

    nss_print_detail("%s IPv%d: %s -> %s %s %s (%d Bytes)\n",
        nss_get_realtime(pk->ts),
        IP_V(pIp),
        ipSrc,
        ipDst,
        nss_get_protocol_name(pIp->ip_p),
        nss_ip_getInfo(pIp),
        pk->len
    );
}

const char* nss_ip_getInfo(const nss_ip_t* ip)
{
    assert(ip);

    static char retStr[50];
    sprintf(retStr, "id = %d, ttl = %d%c",
        ip->ip_id,
        ip->ip_ttl,
        '\0'
    );

    return retStr;
}