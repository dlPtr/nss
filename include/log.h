#ifndef _LOG_H
#define _LOG_H

#if defined(__WINDOWS__) || defined(_WIN32) ||\
	defined(_MSC_VER) || defined(_WIN64)
#define nss_log(LOG_CLASS, format, ...) fprintf(stderr, format, __VA_ARGS__)

#elif defined(linux) || defined(__linux__)
#include <syslog.h>
#define nss_log syslog

#else
#define nss_log(LOG_CLASS, format, ...) do{}while(0)
#endif

#define nss_print_err(...) do {     \
    fprintf(stderr, "nss: ");       \
    fprintf(stderr, __VA_ARGS__);   \
} while(0)


#define nss_print_info(...) do {    \
    printf("nss: ");                \
    printf(__VA_ARGS__);            \
} while(0)

#define nss_print_detail(...) do {    \
    printf(__VA_ARGS__);              \
} while(0)

#endif /* _LOG_H */
