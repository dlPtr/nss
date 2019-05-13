#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include "callback.h"
#include "utils.h"

int nss_callback_analyze(pcap_t* handle, const nss_opt_t opt)
{
    assert(handle);

    int ret = NSS_SUCCESS;

    char* filename = nss_gen_filename();

    ret = nss_callback_dump(handle, filename, opt.count);
    if (ret)
        goto finish;
    
    pid_t pid = fork();
    if (0 == pid)
        execlp("python3", "python3", opt.script, NULL);
    else
        wait(NULL);

finish:
    return ret;
}