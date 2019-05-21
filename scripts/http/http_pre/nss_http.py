import dpkt
import gzip

def nss_get_http(filename):
    '''
nss_get_http() returns a turple (request, response) read from .pcap file.

    type of (request/response) is dict: {
        "method"/"reason": <class str>
        "uri"/"status": <class str>
        "version": <class str>
        "src": <class str> # ip source
        "dst": <class str> # ip destination
        "headers": <class 'collections.OrderedDict'> # General http headers
        "body": <class str> # Only 'POST' Request and Response has body
    }
    '''
    request  = []
    response = []
    
    # Open .pcap file
    f = open(filename, "rb")
    # Read from fileobject
    pcap = dpkt.pcap.Reader(f)
    # For each packet in the pcap process the contents
    
    for timestamp, buf in pcap:
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now grab the data within the Ethernet frame (the IP packet)
        ip = eth.data
        # Check for TCP in the transport layer
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        # Set the TCP data
        tcp = ip.data
        
        # Now see if we can parse the contents as a HTTP request
        try:
            mess = dpkt.http.Request(tcp.data)

            req_dict = {}
            req_dict["method"] = mess.method
            req_dict["uri"] = mess.uri
            req_dict["version"] = mess.version
            req_dict["src"] = \
                str(ip.src[0])\
                + '.' + str(ip.src[1])\
                + '.' + str(ip.src[2])\
                + '.' + str(ip.src[3])
            req_dict["dst"] = \
                str(ip.dst[0])\
                + '.' + str(ip.dst[1])\
                + '.' + str(ip.dst[2])\
                + '.' + str(ip.dst[3])
            req_dict["seq"] = tcp.seq
            req_dict["headers"] = mess.headers

            if "POST" == mess.method:
                req_dict["body"] = mess.body

            request.append(req_dict)
            continue
        except:
            pass

        # Now see if we can parse the contents as a HTTP response
        try:
            mess = dpkt.http.Response(tcp.data)

            res_dict = {}
            res_dict["reason"] = mess.reason
            res_dict["status"] = mess.status
            res_dict["version"] = mess.version
            res_dict["src"] = \
                str(ip.src[0])\
                + '.' + str(ip.src[1])\
                + '.' + str(ip.src[2])\
                + '.' + str(ip.src[3])
            res_dict["dst"] = \
                str(ip.dst[0])\
                + '.' + str(ip.dst[1])\
                + '.' + str(ip.dst[2])\
                + '.' + str(ip.dst[3])
            res_dict["seq"] = tcp.seq
            res_dict["headers"] = mess.headers
            
            # Check if has content-encoding and decode if has
            
            if "content-length" in mess.headers.keys():
                if "content-encoding" in mess.headers.keys():
                    if ("gzip" in mess.headers["content-encoding"]):
                        res_dict["body"] = gzip.decompress(mess.body)
                    elif ("deflate" in mess.headers["content-encoding"]):
                        res_dict["body"] = zlib.decompress(mess.body)
                    else:
                        res_dict["body"] = mess.body
                else:
                    res_dict["body"] = mess.body

            response.append(res_dict)
            continue
        except:
            pass

    f.close()
    return (request, response)

def nss_gen_report(message, pattern, result):
    '''
    Generate report based on:
            1. http message<dict>,
            2. regex pattern<str>,
            3. search result<string>.
    return a string.
    '''
    if "uri" in message:
        return "[%-4x] [%-6s]  [%-20s] [%-15s] -> [%-15s] [%-20s] [%-20s]" %(\
             message["seq"],\
             message["method"],\
             message["headers"].get("host", "") + message["uri"],\
             message["src"],\
             message["dst"],\
             "\"" + pattern + "\"",\
             "\"" + result.group(0) + "\"",\
        )
    elif "status" in message:
        return "[%-4x] [%-6s]  [%-15s] -> [%-15s] [%-20s] [%-20s]" %(\
             message["seq"],\
             message["reason"],\
             message["src"],\
             message["dst"],\
             "\"" + pattern + "\"",\
             "\"" + result.group(0) + "\"",\
        )
    else:
        return "Generate failed."

def nss_sql_print_format(isRequest = True):
    nss_gen_report_format("SQL", isRequest)
def nss_xss_print_format(isRequest = True):
    nss_gen_report_format("XSS", isRequest)

def nss_gen_report_format(prefix="http", isRequest = True):
    if isRequest:
        _nss_print('-' * 92, False, prefix)
        _nss_print("%-8s\t%-8s\t%-8s\t%-8s->%-8s\t%-8s\t%-8s |" %(\
            "Tcp-Seq",\
            "Method",\
            "Referer",\
            "IP-Src",\
            "IP-Dst",\
            "Pattern",\
            "Result",\
            ),
            False,
            prefix
        )
        _nss_print('-' * 92, False, prefix)
    else:
        _nss_print('-' * 76, False, prefix)
        _nss_print("%-8s\t%-8s\t%-8s->%-8s\t%-8s\t%-8s |" %(\
            "Tcp-Seq",\
            "Reason",\
            "IP-Src",\
            "IP-Dst",\
            "Pattern",\
            "Result",\
            ),
            False,
            prefix
        )
        _nss_print('-' * 76, False, prefix)

def _nss_print(str="", error=False, prefix="http"):
    if not error:
        print("\033[1;32m%s +\033[0m " % (prefix) + str)
    else:
        print("\033[1;31m%s +\033[0m " % (prefix)+ str)

def nss_sql_print(str="", error=False):
    _nss_print(str, error, "SQL")
    
def nss_xss_print(str="", error=False):
    _nss_print(str, error, "XSS")

def nss_evil_print(str, prefix="HTTP"):
    print("\033[1;31m%s + %s\033[0m" % (prefix, str))
