#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pcap/pcap.h>
#include <signal.h>
#include "captrue_alive.h"
#include "nss_getopt.h"
#include "nss_filter.h"
#include "callback.h"
#include "nss.h"
#include "log.h"
#include "utils.h"

extern nss_opt_t nss_opt;
static char errBuf[PCAP_ERRBUF_SIZE];

pcap_t* captrue_sigPara;

void nss_captrue_sigint_handler(int sig);

void nss_print_errBuf(void)
{
    nss_print_err("%s\n", errBuf);
}

int nss_check_interface(void)
{
    pcap_if_t* devList = NULL;

    if (0 != pcap_findalldevs(&devList, errBuf)) {
        nss_print_err("No available interfaces!\n");
        return NSS_FAILED;
    }

    /* 如果用户未配置网卡，则默认使用第一块可用网卡 */
    if (!nss_opt.interface) {
        nss_opt.interface = strdup(devList->name);
        if (!nss_opt.interface) {
            pcap_freealldevs(devList);
            return NSS_NOMEM;
        }
    }
    /* 否则遍历所有网卡，确保用户配置的网卡有效 */
    else {  
        pcap_if_t* item = devList;
        while (item) {
            if (0 == strcmp(nss_opt.interface, item->name))
                break;
            item = item->next;
        }
        if (NULL == item) {
            nss_print_err("interface is not valid!\n");
            pcap_freealldevs(devList);
            return NSS_FAILED;
        }
    }

    pcap_freealldevs(devList);
    return NSS_SUCCESS;
}

pcap_t* nss_create_handle(void)
{
    return pcap_create(nss_opt.interface, errBuf);
}

int nss_set_option(pcap_t* handle)
{
    assert(handle);

    int ret = 0;

    ret =pcap_set_promisc(handle, nss_opt.promisc);
    if (ret) {
        nss_print_err("Set promisc failed!\n");
        return NSS_FAILED;
    }

    ret = pcap_set_snaplen(handle, nss_opt.snapLen == 0 ? 65535 : nss_opt.snapLen);
    if (ret) {
        nss_print_err("Set snaplen failed!\n");
        return NSS_FAILED;
    }
}

int nss_activate_handle(pcap_t* handle)
{
    return pcap_activate(handle);
}

int nss_captrue_alive(int argc, char* argv[])
{
    int ret = 0;

    /* 1. Find available interfaces */
    ret = nss_check_interface();
    if (ret)
        goto finish2;

    /* 2. Create handle */
    pcap_t* handle = NULL;
    handle = nss_create_handle();
    if (!handle) {
        nss_print_err("handle create failed!");
        ret = NSS_FAILED;
        goto finish2;
    }

    /* 3. Set appropriate options and Activate */
    ret = nss_set_option(handle);
    if (ret)
        goto finish;
    ret = nss_activate_handle(handle);
    if (ret)
        goto finish;

    captrue_sigPara = handle;
    signal(SIGINT, nss_captrue_sigint_handler);

    /* 4. Set filter */
    ret = nss_set_filter(handle, nss_opt);
    if (NSS_SUCCESS != ret)
        goto finish;

    if (nss_if_analyze())
        nss_print_info("In captrue mode, --script option ignored.\n");
    nss_print_detail("Listening on interface %s, Data-Link Layer type: %s(%s)\n",\
            nss_opt.interface, nss_get_dltType(handle), nss_get_dltDesc(handle));
    
    /* 5. Captrue packets */
    /* If user wants to store file */
    if (nss_if_dump())
        ret = nss_callback_dump(handle, nss_opt.wFileName, nss_opt.count);
    else
        ret = nss_callback_print(handle, nss_opt.count);

finish:
    /* 6. If not SIGINT, auto */
    pcap_close(handle);
finish2:
    return ret;
}

void nss_captrue_sigint_handler(int sig)
{
    assert(captrue_sigPara);
    
    putchar(10);
    puts("--- NSS live Captrue Statistics ---");

    struct pcap_stat stat;
    pcap_stats(captrue_sigPara, &stat);

    nss_print_detail("%u packets received\n", stat.ps_recv);
    nss_print_detail("%u packets dropped by filter\n", stat.ps_drop);
    nss_print_detail("%u packets dropped by interface\n", stat.ps_ifdrop);

    pcap_breakloop(captrue_sigPara);
}