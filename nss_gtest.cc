#include <gtest/gtest.h>
#include "captrue_alive.h"
#include "read_offline.h"
#include "nss_getopt.h"
#include "log.h"
#include <stdio.h>

int g_argc;
char** g_argv;

int nss_run(int argc, char* argv[])
{
        /* 获取所有选项及参数 */
        nss_option_get(argc, argv);

            int ret = 0;

                if (nss_if_captrueMode())
                            /* Captrue Mode */
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

TEST(nss_run, default)
{
    EXPECT_TRUE(!nss_run(g_argc, g_argv));
}

int main(int argc, char* argv[])
{
    g_argc = argc;
    g_argv = argv;

    testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
