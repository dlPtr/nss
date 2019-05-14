import http_pre.nss_http as hp
from urllib.parse import unquote
import sys
import os
import re

sql_dict_name = "sql.dict"

def nss_search(sql_list, target):
#     print(str(target))
    for item in sql_list:
        res = re.search(item, unquote(str(target)).replace('+', ' '))
        if res:
            print("%-20s%s%s" %(target["uri"], str(target["body"]), str(res)))

def nss_gen_list(dictname):
    sql_list = []
    for eachline in open(realPath, "r"):
        sql_list.append(eachline.strip('\n'))
    return sql_list



realPath = os.path.split(os.path.realpath(__file__))[0] + "/dict/" + sql_dict_name
sql_list = nss_gen_list(sql_dict_name)
request, response = hp.nss_get_http(sys.argv[1])

# for i in range(len(response)):
#     if "text" in response[i]["headers"]["content-type"]:
#         nss_search(sql_list, response[i])

for i in range(len(request)):
    nss_search(sql_list, request[i])