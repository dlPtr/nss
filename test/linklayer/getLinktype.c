#include <pcap/pcap.h>
#include <stdio.h>

int main()
{
    char err[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_create("ens33", err);
    pcap_activate(handle);

    int *arr;
    int size = pcap_list_datalinks(handle, &arr);

    for (int i = 0; i < size; i++) {
        printf("%d %s\n", arr[i], pcap_datalink_val_to_name(arr[i]));
    }

    pcap_free_datalinks(arr);

    printf("%d\n", pcap_datalink(handle));

    return 0;
}
