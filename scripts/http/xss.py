import http_pre.nss_http as hp
from urllib.parse import unquote
import sys, os, re

def nss_gen_list(dictname):
    xss_dict = []
    sql_dict_path = os.path.split(os.path.realpath(__file__))[0] + "/dict/" + dictname
    for eachline in open(sql_dict_path, "r"):
        xss_dict.append(eachline.strip('\n'))
    return xss_dict

def _nss_search(message, xss_dict):
    '''
    return [messgae, [sql_pattern], [search_result]]
    '''
    ret = [message, [], []]
    target = unquote(str(message)).replace('+', ' ')
    for item in xss_dict:
        res = re.search(item, target)
        if None != res:
            ret[1].append(item)
            ret[2].append(res)
    return ret

def nss_search(message, sql_dict_name):
    '''
    return a list contains list->[messgae, [sql_pattern], [search_result]]
    '''
    result = []
    xss_dict = nss_gen_list(sql_dict_name)
    for index in range(len(message)):
        li = _nss_search(message[index], xss_dict)
        result.append(li)
    return result

def main():
    hp.nss_xss_print("Python3 Receive \"%s\" from C" % (sys.argv[1]))

    # Get Sample(.pcap file from C)
    hp.nss_xss_print("Parsing file..")
    try:
        request, response = hp.nss_get_http(sys.argv[1])
    except:
        hp.nss_xss_print("Parse failed, check if packages contain http part", True)
        hp.nss_xss_print("Python3 quit..\n", True)
        exit(-1)

    hp.nss_xss_print()

    # handle Request
    hp.nss_xss_print("Handling Request Packages..")
    try:
        ret = nss_search(request, "xss.dict")
        hp.nss_xss_print_format()
        for i in ret:
            for j in range(len(i[1])):
                try:
                    hp.nss_evil_print(hp.nss_gen_report(i[0], i[1][j], i[2][j]), "XSS")
                except:
                    hp.nss_xss_print("Error detected when generate Request reports..")
                    hp.nss_xss_print("Python3 quit..\n", True)
    except:
        hp.nss_xss_print("Regex matching error deteced..", True)
        hp.nss_xss_print("Python3 quit..\n", True)
        exit(-1)

    hp.nss_xss_print()

    # handle Response
    hp.nss_xss_print("Handling Response Packages..")
    try:
        ret = nss_search(response, "xss.dict")
        hp.nss_xss_print_format(False)
        for i in ret:
            for j in range(len(i[1])):
                try:
                    hp.nss_evil_print(hp.nss_gen_report(i[0], i[1][j], i[2][j]), "XSS")
                except:
                    hp.nss_xss_print("Error detected when generate Response reports..")
                    hp.nss_xss_print("Python3 quit..\n", True)
    except:
        hp.nss_xss_print("Regex matching error dected..", True)
        hp.nss_xss_print("Python3 quit..\n", True)
        exit(-1)

    hp.nss_xss_print()

    hp.nss_xss_print("Python3 quit..\n")

if __file__ == "./scripts/http/xss.py":
    main()
