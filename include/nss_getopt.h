#ifndef _NSS_GETOPT_H
#define _NSS_GETOPT_H

#include "nss.h"

struct Nss_opt {
    /* 1. Set-up option */
    char* interface;
    u_int snapLen;
    u_int count;
    nss_bool promisc;

    nss_bool ifWrite;
    char* wFileName;
    nss_bool ifRead;
    char* rFileName;

    /* 2. Filter option */
    /* 2.1 type */
    char* host;
    char* net;
    char* port;
    char* portRange;
    /* 2.2 dir */
    char* src;
    char* dst;
    /* 2.3 proto */
    char* proto;
    /* 2.4 DIY */
    char* bpfstring;

    /* 3. Analyze option */
    char* script;
    
};
typedef struct Nss_opt nss_opt_t;

const char* nss_get_version(void);
void nss_print_version(void);
void nss_print_usage(void);
int nss_option_get(int argc, char** argv);
void nss_option_free(void);

/* judge if captrue(or read from file) */
nss_bool nss_if_captrueMode(void);
/* judge if store .pcap */
nss_bool nss_if_dump(void);
/* judge if analyze */
nss_bool nss_if_analyze(void);
/* return file to read */
const char* nss_get_rFileName(void);
/* return file to write */
const char* nss_get_wFileName(void);
/* return option.count */
int nss_get_count(void);

#endif /* _NSS_GETOPT_H  */
