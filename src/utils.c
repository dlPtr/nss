#include "callback.h"
#include <net/ethernet.h>
#include <assert.h>
#include <time.h>

void nss_ip_ntoa(u_int addr, char* string)
{
    assert(string);

    sprintf(string, "%d.%d.%d.%d%c",
        (addr & 0x000000FF) >> (8 * 0),
        (addr & 0x0000FF00) >> (8 * 1),
        (addr & 0x00FF0000) >> (8 * 2),
        (addr & 0xFF000000) >> (8 * 3),
        '\0'
    );
}

char* nss_get_realtime(struct timeval stv)
{
    static char retStr[50];

    struct tm now;
    localtime_r(&stv.tv_sec, &now);

    sprintf(retStr, "%02d:%02d:%02d.%ld%c",
        now.tm_hour,
        now.tm_min,
        now.tm_sec,
        stv.tv_usec % 1000000,
        '\0'
    );

    return retStr;
}

char* nss_gen_filename(void)
{
    static char retStr[100];

    struct timeval stv;
    gettimeofday(&stv, NULL);

    struct tm now;
    localtime_r(&stv.tv_sec, &now);

    sprintf(retStr, "./.samples/%4d-%02d-%02d_%02d:%02d:%02d.pcap",
        now.tm_year + 1900,
        now.tm_mon + 1,
        now.tm_mday,
        now.tm_hour,
        now.tm_min,
        now.tm_sec
    );

    return retStr;
}

const char* nss_get_protocol_name(u_char typeNum)
{
    const char* pStr = NULL;

    switch (typeNum) {
        case IPPROTO_TCP:   pStr = "TCP";  break;
        case IPPROTO_UDP:   pStr = "UDP";  break;
        case IPPROTO_ICMP:  pStr = "ICMP"; break;
        case IPPROTO_IGMP:  pStr = "IGMP"; break;
        default: pStr = "";
    }

    return pStr;
}

void nss_mac_ntoa(const u_char *arr, char* string)
{
    assert(arr);
    assert(string);

    sprintf(string, "%02x.%02x.%02x.%02x.%02x.%02x%c",\
        arr[0], arr[1], arr[2],\
        arr[3], arr[4], arr[5],\
        '\0'
    );
}

const char* nss_get_dltType(pcap_t* handle)
{
    assert(handle);

    int dltType = pcap_datalink(handle);
    assert(PCAP_ERROR_NOT_ACTIVATED != dltType);

    return pcap_datalink_val_to_name(dltType);
}

const char* nss_get_dltDesc(pcap_t* handle)
{
    assert(handle);
    
    int dltType = pcap_datalink(handle);
    assert(PCAP_ERROR_NOT_ACTIVATED != dltType);

    return pcap_datalink_val_to_description(dltType);
}