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
    # Open .pcap file
    f = open(filename, "rb")
    # Read from fileobject
    pcap = dpkt.pcap.Reader(f)
    # For each packet in the pcap process the contents
    request  = []
    response = []
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
            req_dict["headers"] = mess.headers

            if "POST" == mess.method:
                req_dict["body"] = mess.body

            request.append(req_dict)
            continue
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
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
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            pass

    f.close()
    return (request, response)
