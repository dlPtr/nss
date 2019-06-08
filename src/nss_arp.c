#include "nss_arp.h"
#include "log.h"
#include "utils.h"
#include <assert.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <string.h>

void nss_callback_print_arp(const struct pcap_pkthdr* pk, const u_char* packet)
{
    assert(pk);
    assert(packet);

    nss_arp_t* pArp = (nss_arp_t*)(packet + 14);

    /* Get mac string */
    char srcMac[20];
    char dstMac[20];
    nss_mac_ntoa(pArp->arp_sha, srcMac);
    nss_mac_ntoa(pArp->arp_tha, dstMac);

    /* 0x08 for IP */
    if (pArp->arp_pro != 0x08)
        nss_print_err("Unknown arp protocol type %d\n", pArp->arp_pro);
    else {
        nss_print_detail("%s ARP: %s -> %s Info: %s (%d Bytes)\n",
            nss_get_realtime(pk->ts),
            srcMac,
            (0 == strcmp(dstMac, "00.00.00.00.00.00")) ? "Broadcast" : dstMac,
            nss_arp_getInfo(pArp),
            pk->len
        );
    }
}

const char* nss_arp_getInfo(const nss_arp_t* pArp)
{
    assert(pArp);

    static char retStr[50];

    char ipSrc[12];
    char ipDst[12];
    nss_arp_get_ip(pArp->arp_spa, ipSrc);
    nss_arp_get_ip(pArp->arp_tpa, ipDst);

    char srcMac[20];
    char dstMac[20];
    nss_mac_ntoa(pArp->arp_sha, srcMac);
    nss_mac_ntoa(pArp->arp_tha, dstMac);

    if (0x0100 == pArp->arp_op) {
        sprintf(retStr, "\"Who is %s? Please tell %s\"%c",
            ipDst,
            ipSrc,
            '\0'
        );
    }
    else if (0x0200 == pArp->arp_op) {
        sprintf(retStr, "\"%s is at %s\"%c",
            ipSrc,
            srcMac,
            '\0'
        );
    }
    else {
        sprintf(retStr, "Unkown arp opcode %d%c", pArp->arp_op, '\0');
    }

    return retStr;
}

void nss_arp_get_ip(const u_char* arr, char* ip)
{
    assert(arr);
    assert(ip);

    sprintf(ip, "%d.%d.%d.%d%c",
        arr[0],
        arr[1],
        arr[2],
        arr[3],
        '\0'
    );
}

const char* nss_arp_get_type(int op)
{
    if (0x0100 == op || 0x0200 == op)
        return "ARP";
    else if (0x0300 == op || 0x0400 == op)
        return "RARP";
    else
        return "";
}