#ifndef _CAPTRUE_ALIVE_H
#define _CAPTRUE_ALIVE_H

#include <pcap/pcap.h>

/* 打印errBuf */
void nss_print_errBuf(void);

/* 检查并获取有效网卡 */
int nss_check_interface(void);
/* 创建句柄 */
pcap_t* nss_create_handle(void);
/* 配置捕获参数 */
int nss_set_option(pcap_t* handle);
/* 激活句柄 */
int nss_activate_handle(pcap_t* handle);
/* Close handle */
void nss_close_handle();

/* core */
int nss_captrue_alive(int argc, char* argv[]);

#endif /* _CAPTRUE_ALIVE_H */
