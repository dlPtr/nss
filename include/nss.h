#ifndef _NSS_H
#define _NSS_H

#include <pcap/pcap.h>

typedef enum {
    NSS_FALSE=0, NSS_TRUE=1
} nss_bool;

#define NSS_SUCCESS  0
#define NSS_FAILED  -1
#define NSS_NOMEM   -2
#define NSS_BADPARA -3
#define NSS_ARGERR  -4

#define HTTP_SCRIPT_DIR  "./scripts/http/"
#define SAMPLE_DIR  "./.samples/"

/* Run!! */
int nss_run(int argc, char* argv[]);

#endif /* _NSS_H */
