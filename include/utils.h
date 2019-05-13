#ifndef _UTILS_H
#define _UTILS_H

#include <pcap/pcap.h>

#define NSS_FREE(P) \
if (P) {            \
    free(P);        \
    P = NULL;       \
}

/* get protocol string */
const char* nss_get_protocol_name(u_char typeNum);
/* uint to string */
void nss_ip_ntoa(u_int addr, char* string);
/* get real time string for package */
char* nss_get_realtime(struct timeval stv);
/* generate cap file name based on current time */
char* nss_gen_filename(void);
/* transfer mac array to string  */
void nss_mac_ntoa(const u_char *arr, char* string);

/* 获取链路层类型 */
const char* nss_get_dltType(pcap_t* handle);
/* 获取链路层miaoshu */
const char* nss_get_dltDesc(pcap_t* handle);

#endif /* _UTILS_H */