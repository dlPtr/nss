#ifndef _CALLBACK_H
#define _CALLBACK_H

#include "nss.h"
#include "nss_getopt.h"

/* Write to File */
void nss_callback_svPkt(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int nss_callback_dump(pcap_t* handle, const char* fileName, int count);

/* Print to Screen */
int nss_callback_print(pcap_t* handle, int count);

/* Analyze packets using python */
int nss_callback_analyze(pcap_t* handle, nss_opt_t opt);

#endif /* _CALLBACK_H */