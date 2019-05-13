#include <assert.h>
#include <net/ethernet.h>
#include "callback.h"
#include "log.h"
#include "nss_ether.h"
#include "nss_ip.h"
#include "nss_arp.h"
#include "nss_rarp.h"
#include "nss_pup.h"

void nss_callback_netLayer(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    assert(pkthdr);
    assert(packet);

    nss_ether_t* pHd = NULL;

    pHd = (nss_ether_t*)packet;

    switch (ntohs(pHd->type)) {
        case ETHERTYPE_IP: {
            nss_callback_print_ip(pkthdr, packet);
            break;
        }
        case ETHERTYPE_ARP: {
            nss_callback_print_arp(pkthdr, packet);
            break;
        }
        case ETHERTYPE_REVARP: {
            nss_callback_print_rarp(pkthdr, packet);
            break;
        }
        case ETHERTYPE_PUP: {
            nss_callback_print_pup(pkthdr, packet);
            break;
        }
        default: {
            nss_print_err("Unknown net layer protocol packet caught, ethernet type %X\n",
                pHd->type);
        }
    }

    // int ti = 0xfff;
    // int tj = 0xffff;
    // while(--ti)
    //     while(--tj){}
}

int nss_callback_print(pcap_t* handle, int count)
{
    assert(handle);
    assert(count >= 0);

    int ret = pcap_loop(handle, (count == 0 ? -1 : count), nss_callback_netLayer, NULL);
    if (PCAP_ERROR == ret) {
        nss_print_err("Loop error detected\n");
        return NSS_FAILED;
    }
        
    return NSS_SUCCESS;
}





