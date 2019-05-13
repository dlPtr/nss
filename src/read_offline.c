#include <pcap/pcap.h>
#include <sys/wait.h>
#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include "read_offline.h"
#include "nss_getopt.h"
#include "callback.h"
#include "nss_filter.h"
#include "utils.h"
#include "nss.h"
#include "log.h"

pcap_t* read_sigPara;
extern nss_opt_t nss_opt;

void nss_read_sigint_handler(int sig);

int nss_read_offline(int argc, char* argv[])
{
    int ret = NSS_SUCCESS;

    char errBuf[PCAP_ERRBUF_SIZE];
    const char* fn = nss_get_rFileName();

    /* 1. Read from file */
    pcap_t* handle = pcap_open_offline(fn, errBuf);
    if(!handle) {
        nss_print_err("Open %s failed, no such file!\n", fn);
        return NSS_FAILED;
    }

    read_sigPara = handle;
    signal(SIGINT, nss_read_sigint_handler);

    nss_print_detail("Reading file %s, Data-Link Layer type: %s(%s)\n\n",
            fn, nss_get_dltType(handle), nss_get_dltDesc(handle));

    /* 2. Set filter */
    ret = nss_set_filter(handle, nss_opt);
    if (ret)
        return ret;

    /* 3. handle packets */
    /* If user wants to analyze packets */
    if (nss_if_analyze())
        ret = nss_callback_analyze(handle, nss_opt);
    /* If user wannna JUST print to screen */
    else
        ret = nss_callback_print(handle, nss_get_count());

    /* 3. Close handle */
    pcap_close(handle);

    return ret;
}

void nss_read_sigint_handler(int sig)
{
    assert(read_sigPara);

    putchar(10);

    if (!nss_if_analyze())
        exit(NSS_SUCCESS);
    /* In case of zombie process */
    else
        wait(NULL);
        
}