import http_pre.nss_http as hp

def sample_get_http():
    q, s = hp.nss_get_http("./../sample.pcap")

    print("------Request------")
    print(q[0]["method"])
    print(q[0]["uri"])
    print(q[0]["version"])
    print(q[0]["src"])
    print(q[0]["dst"])
    print(q[0]["headers"])
    print(q[0].get("body", "No body"))
    print()
    print("------Response------")
    print(s[0]["reason"])
    print(s[0]["status"])
    print(s[0]["version"])
    print(s[0]["src"])
    print(s[0]["dst"])
    print(s[0]["headers"])
    # print(s[0].get("body", "No body"))

    # help(hp.nss_get_http)

if __name__ == "__main__":
    
    # 1. get http content
    sample_get_http()