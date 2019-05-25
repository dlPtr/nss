#ifndef _NSS_FILTER_H
#define _NSS_FILTER_H

#include <pcap/pcap.h>

/* Set bpf filter for handle */
int nss_set_filter(pcap_t* handle, nss_opt_t nss_opt);
/* Generate filter string */
const char* nss_gen_filter(nss_opt_t nss_opt);

#endif /* _NSS_FILTER_H */