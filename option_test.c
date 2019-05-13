#include "getOpt.h"
#include "nss.h"
#include "log.h"
#include <stdio.h>

extern nss_opt_t nss_opt;

int main(int argc, char* argv[])
{
    if (nss_option_get(argc, argv)) {
        nss_print_err("nss_option_get failed!\n");
        nss_option_free();
        return -1;
    }

    printf("interface: %s, snaplen: %d, count: %d\n",\
            nss_opt.interface, nss_opt.snapLen, nss_opt.count);
    printf("promisc mode: %s, isWrite: %s, ifRead: %s, filename: %s-%s\n",\
            nss_opt.promisc == TRUE ? "TRUE" : "FALSE",
            nss_opt.ifWrite == TRUE ? "TRUE" : "FALSE",
            nss_opt.ifRead == TRUE ? "TRUE" : "FALSE",
            nss_opt.wFileName,
            nss_opt.rFileName);

    nss_option_free();

    return 0;
}
