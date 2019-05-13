#include <pcap/pcap.h>
#include <assert.h>
#include "log.h"
#include "nss_getopt.h"
#include "nss_filter.h"

int nss_set_filter(pcap_t* handle, nss_opt_t nss_opt)
{
    assert(handle);

    struct bpf_program filter;
    if(pcap_compile(handle, &filter, nss_gen_filter(nss_opt), 1, 0)) {
        nss_print_err("bpf filter compile error, check your syntax.\n");
        return NSS_FAILED;
    }
    if (pcap_setfilter(handle, &filter))
        return NSS_FAILED;

    pcap_freecode(&filter);

    return NSS_SUCCESS;
}

#define NSS_PADD_FILTER(option, value)\
if (value)                            \
    sprintf(nss_filter, "%s and %s %s",\
        nss_filter,                    \
        option,                        \
        value                          \
    );
const char* nss_gen_filter(nss_opt_t opt)
{
    static char nss_filter[100];

    if (opt.script) {
        sprintf(nss_filter, "%s", "port 80");
        return nss_filter;
    }

    if (opt.bpfstring) {
        sprintf(nss_filter, "%s", opt.bpfstring);
        return nss_filter;
    }

    sprintf(nss_filter, "len > 0");
    NSS_PADD_FILTER("host", opt.host);
    NSS_PADD_FILTER("net",  opt.net);
    NSS_PADD_FILTER("port", opt.port);
    NSS_PADD_FILTER("portrange", opt.portRange);
    NSS_PADD_FILTER("src", opt.src);
    NSS_PADD_FILTER("dst", opt.dst);
    if (opt.proto)
        sprintf(nss_filter, "%s and %s", nss_filter, opt.proto);

    return nss_filter;
}