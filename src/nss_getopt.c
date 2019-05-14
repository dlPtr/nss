#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include "nss_getopt.h"
#include "nss.h"
#include "log.h"
#include "utils.h"

nss_opt_t nss_opt;

const char* nss_get_version(void)
{
    return "v1.1.5";
}

void nss_print_version(void)
{
    printf("nss version %s,%s\n", nss_get_version(), pcap_lib_version());
}

void nss_print_usage(void)
{
    system("cat nss.figlet | lolcat || cat nss.figlet");
    
    // putchar(10);

    nss_print_version();

    puts("----------------------------------------------");
    puts("Usage: nss[options.. [parameters...]]");

    puts("\nSet-Up options:");
    printf("  %-15s\t%-s\n",\
"-i interface", "指定捕获数据包的网卡;未配置时该参数时则默认使用nss可获取的网卡列表的第一个.");
    printf("  %-15s\t%-s\n",\
"-l snaplen", "设置捕获包时所需捕获的长度，这个参数用处在于仅需要包的一部分信息时，例如捕获头字段");
    printf("  %-15s\t%-s\n",\
"", "，未配置时则默认捕捉包的长度为65535.");
    printf("  %-15s\t%-s\n",\
"-c count", "设置捕获count个包之后停止;未配置该参数则一直捕捉直至收到终止信号(ctrl+c).");
    printf("  %-15s\t%-s\n",\
"-w filename", "将捕获到的数据包写入至指定文件");
    printf("  %-15s\t%-s\n",\
"-r filename", "从指定文件读取已捕获的数据包");
    printf("  %-15s\t%-s\n",\
"-p --promisc", "开启混杂模式(默认不开启)");
    printf("  %-15s\t%-s\n",\
"-v --version", "版本号");
    printf("  %-15s\t%-s\n",\
"-h --help", "帮助信息");

    puts("\nFilter options:");
    printf("  %-15s\t%-s\n",\
"-H --host address", "截获主机address的所有收到和发出的数据包");
    printf("  %-15s\t%-s\n",\
"-n --net network", "截获网络地址为network的所有数据包");
    printf("  %-15s\t%-s\n",\
"-P --port number", "截获来自端口号number的所有数据包");
    printf("  %-15s\t%-s\n",\
"--portange=n1-n2", "截获来自端口号为n1-n2之间的所有数据包");
    printf("  %-15s\t%-s\n",\
"-s --src address", "截获源地址为address的所有数据包");
    printf("  %-15s\t%-s\n",\
"-d --dst address", "截获目的地址为address的所有数据包");
    printf("  %-15s\t%-s\n",\
"--proto=name", "截获所有为name协议的数据包");
    printf("  %-15s\t%-s\n",\
"-b --bpf bpfstring", "用户可通过该选项自定义符合pcap bpf-filter规则");
    printf("  %-15s\t%-s\n",\
"", "(https://www.tcpdump.org/manpages/pcap-filter.7.html)");
    printf("  %-15s\t%-s\n",\
"", "的过滤表达式。注意：使用该选项时其它过滤规则选项将会失效。");

    puts("\nAnalyze options:");
    printf("  %-15s\t%-s\n",\
"--script-http=xx.py", "使用xx.py对捕获到的http包进行分析");

    putchar(10);
}

/* I:L:C:PW:R:VHh */
int nss_option_get(int argc, char** argv)
{
    assert(argc >= 0);
    assert(argv);

    memset(&nss_opt, 0, sizeof(struct Nss_opt));

    /* Close getopt error report */
    opterr = 0;
   
    int opt;
    const char* short_options = "i:l:c:pw:r:vhH:n:P:s:d:b:";
    const struct option long_options[] = {
        {"help",    no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {"promisc", no_argument, NULL, 'P'},
        {"host", required_argument, NULL, 'H'},
        {"net",  required_argument, NULL, 'n'},
        {"port", required_argument, NULL, 'P'},
#define NSS_PORTRANGE 257
        {"portrange", required_argument, NULL, NSS_PORTRANGE},
        {"src", required_argument, NULL, 's'},
        {"dst", required_argument, NULL, 'd'},
#define NSS_PROTO 258
        {"proto",required_argument, NULL, NSS_PROTO},
        {"bpf",  required_argument, NULL, 'b'},
#define NSS_SCRIPT 259
        {"script-http", required_argument, NULL, NSS_SCRIPT},
        {NULL, 0, NULL, 0}
    };
    while (-1 != (opt = getopt_long(argc, argv, short_options, long_options, NULL))) {
        switch (opt) {
            case 'i': {
                nss_opt.interface = strdup(optarg);
                if (NULL == nss_opt.interface) {
                    nss_print_err("No enough memory when handle option\n");
                    exit(NSS_NOMEM);
                }
                break;
            }
            case 'l': {
                nss_opt.snapLen = atoi(optarg);
                if (nss_opt.snapLen <= 0) {
                    nss_print_err("Invalid length(%s)\n", optarg);
                    exit(NSS_ARGERR);
                }
                break;
            }
            case 'c': {
                nss_opt.count = atoi(optarg);
                if (nss_opt.count <= 0) {
                    nss_print_err("Invalid count(%s)\n", optarg);
                    exit(NSS_ARGERR);
                }
                break;
            }
            case 'p': {
                nss_opt.promisc = NSS_TRUE;
                break;
            }
            case 'w': {
                nss_opt.ifWrite = NSS_TRUE;
                nss_opt.wFileName = strdup(optarg);
                if (NULL == nss_opt.wFileName) {
                    nss_print_err("No enough memory when handle option\n");
                    exit(NSS_NOMEM);
                }
                break;
            }
            case 'r': {
                nss_opt.ifRead = NSS_TRUE;
                nss_opt.rFileName = strdup(optarg);
                if (NULL == nss_opt.rFileName) {
                    nss_print_err("No enough memory when handle option\n");
                    exit(NSS_NOMEM);
                }
                break;
            }
            case 'v': {
                nss_print_version();
                putchar(10);
                exit(NSS_SUCCESS);
            }
            case 'h': {
                nss_print_usage();
                exit(NSS_SUCCESS);
            }
            case 'H': {
                nss_opt.host = strdup(optarg);
                if (NULL == nss_opt.host) {
                    nss_print_err("No enough memory when handle option\n");
                    exit(NSS_NOMEM);
                }
                break;
            }
            case 'n': {
                nss_opt.net = strdup(optarg);
                if (NULL == nss_opt.net) {
                    nss_print_err("No enough memory when handle option\n");
                    exit(NSS_NOMEM);
                }
                break;
            }
            case 'P': {
                nss_opt.port = strdup(optarg);
                if (NULL == nss_opt.port) {
                    nss_print_err("No enough memory when handle option\n");
                    exit(NSS_NOMEM);
                }
                break;
            }
            case NSS_PORTRANGE: {
                nss_opt.portRange = strdup(optarg);
                if (NULL == nss_opt.portRange) {
                    nss_print_err("No enough memory when handle option\n");
                    exit(NSS_NOMEM);
                }
                break;
            }
            case 's': {
                nss_opt.src = strdup(optarg);
                if (NULL == nss_opt.src) {
                    nss_print_err("No enough memory when handle option\n");
                    exit(NSS_NOMEM);
                }
                break;
            }
            case 'd': {
                nss_opt.dst = strdup(optarg);
                if (NULL == nss_opt.dst) {
                    nss_print_err("No enough memory when handle option\n");
                    exit(NSS_NOMEM);
                }
                break;
            }
            case NSS_PROTO: {
                nss_opt.proto = strdup(optarg);
                if (NULL == nss_opt.proto) {
                    nss_print_err("No enough memory when handle option\n");
                    exit(NSS_NOMEM);
                }
                break;
            }
            case 'b': {
                nss_opt.bpfstring = strdup(optarg);
                if (NULL == nss_opt.bpfstring) {
                    nss_print_err("No enough memory when handle option\n");
                    exit(NSS_NOMEM);
                }
                break;
            }
            case NSS_SCRIPT: {
                nss_opt.script = (char*)malloc(strlen(optarg) + sizeof(HTTP_SCRIPT_DIR) + 1);
                if (NULL == nss_opt.script) {
                    nss_print_err("No enough memory when handle option\n");
                    exit(NSS_NOMEM);
                }
                else
                    sprintf(nss_opt.script, "%s%s", HTTP_SCRIPT_DIR, optarg);

                break;
            }
            /* 出现错误的选项时 */
            case '?': {
            }
            default: {
                nss_print_err("Option syntax(%c) error, use -h for help.\n\n",
                    optopt);
                exit(NSS_ARGERR);
            }
        }
    }

    return NSS_SUCCESS;
}

void nss_option_free(void)
{
    NSS_FREE(nss_opt.interface);
    NSS_FREE(nss_opt.wFileName);
    NSS_FREE(nss_opt.rFileName);
    NSS_FREE(nss_opt.host);
    NSS_FREE(nss_opt.net);
    NSS_FREE(nss_opt.port);
    NSS_FREE(nss_opt.portRange);
    NSS_FREE(nss_opt.src);
    NSS_FREE(nss_opt.dst);
    NSS_FREE(nss_opt.proto);
    NSS_FREE(nss_opt.script);

    nss_opt.snapLen = 0;
    nss_opt.count   = 0;
    nss_opt.promisc = NSS_FALSE;
    nss_opt.ifWrite = NSS_FALSE;
    nss_opt.ifRead  = NSS_FALSE;
}

nss_bool nss_if_captrueMode(void)
{
    return !nss_opt.ifRead;
}

nss_bool nss_if_dump(void)
{
    return nss_opt.ifWrite;
}

nss_bool nss_if_analyze(void)
{
    return (NULL != nss_opt.script);
}

const char* nss_get_rFileName(void)
{
    return nss_opt.rFileName;
}

const char* nss_get_wFileName(void)
{
    return nss_opt.wFileName;
}

int nss_get_count(void)
{
    return nss_opt.count;
}
