#include "captrue_alive.h"
#include "read_offline.h"
#include "nss_getopt.h"
#include "log.h"
#include <stdio.h>

int nss_run(int argc, char* argv[])
{
    /* 获取所有选项及参数 */
    nss_option_get(argc, argv);

    int ret = 0;

    if (nss_if_captrueMode())
        ret = nss_captrue_alive(argc, argv);
    else
        /* Read file Mode */
        ret = nss_read_offline(argc, argv);

    nss_option_free();

    if (NSS_SUCCESS != ret)
        nss_log(LOG_INFO, "NSS quit with error code %d..", ret);
    else
        nss_log(LOG_INFO, "NSS quit successfully!");

    return ret;
}

int main(int argc, char* argv[])
{
    nss_log(LOG_INFO, "Start running.");

    return nss_run(argc, argv);
}