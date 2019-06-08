import http_pre.nss_http as hp
from urllib.parse import unquote
import sys, os, re

def nss_gen_list(dictname):
    sql_list = []
    sql_dict_path = os.path.split(os.path.realpath(__file__))[0] + "/dict/" + dictname
    for eachline in open(sql_dict_path, "r"):
        sql_list.append(eachline.strip('\n'))
    return sql_list

def _nss_search(message, sql_list):
    '''
    return [messgae, [sql_pattern], [search_result]]
    '''
    ret = [message, [], []]
    target = unquote(str(message)).replace('+', ' ')
    for item in sql_list:
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
    sql_list = nss_gen_list(sql_dict_name)
    for index in range(len(message)):
        li = _nss_search(message[index], sql_list)
        result.append(li)
    return result

hp.nss_sql_print("Python3 Receive \"%s\" from C" % (sys.argv[1]))

# Get Sample(.pcap file from C)
hp.nss_sql_print("Parsing file..")
try:
    request, response = hp.nss_get_http(sys.argv[1])
except:
    hp.nss_sql_print("Parse failed, check if packages contain http part", True)
    hp.nss_sql_print("Python3 quit..\n", True)
    exit(-1)

hp.nss_sql_print()

# handle Request
hp.nss_sql_print("Handling Request Packages..")
try:
    ret = nss_search(request, "sql.dict")
    hp.nss_sql_print_format()
    for i in ret:
        for j in range(len(i[1])):
            try:
                hp.nss_evil_print(hp.nss_gen_report(i[0], i[1][j], i[2][j]), "SQL")
            except:
                hp.nss_sql_print("Error detected when generate Request reports..")
                hp.nss_sql_print("Python3 quit..\n", True)
except:
    hp.nss_sql_print("Regex matching error dected..", True)
    hp.nss_sql_print("Python3 quit..\n", True)
    exit(-1)

hp.nss_sql_print()

# handle Response
hp.nss_sql_print("Handling Response Packages..")
try:
    ret = nss_search(response, "sql.dict")
    hp.nss_sql_print_format()
    for i in ret:
        for j in range(len(i[1])):
            try:
                hp.nss_evil_print(hp.nss_gen_report(i[0], i[1][j], i[2][j]), "SQL")
            except:
                hp.nss_sql_print("Error detected when generate Response reports..")
                hp.nss_sql_print("Python3 quit..\n", True)
except:
    hp.nss_sql_print("Regex matching error dected..", True)
    hp.nss_sql_print("Python3 quit..\n", True)
    exit(-1)

hp.nss_sql_print()

hp.nss_sql_print("Python3 quit..\n")
