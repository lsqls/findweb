#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import commands
import sys
import re
import time
import ast
import urllib2
import shodan
API_KEY = "QSKIf8ayEM59QrUwB29vk5xTNpsm1WzB"
LINKS ,webip= [],[]
def  findsub(domain):
    cmd='subDomainsBrute.py -o  %s %s'%(domain,domain)
    print 'run "%s"'%cmd
    os.system(cmd)
def  parse(domain):
    IPS=[]
    with  open(domain, "r") as f:
            info = f.read()
            f.close()
            ippattern = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
            iplist = re.findall(ippattern, info)
            iplist=filter(lambda x: x.split('.')[0] != ('10' or '127' or '192' or '172'), iplist)
            iplist=map(lambda x: x.split('.')[0] + '.' + x.split('.')[1] + '.0.0', iplist)
            for  ip  in iplist:
                if  ip not  in  IPS:
                    IPS.append(ip)
    with  open('%s.txt'%domain, "w") as f:
        for  IP  in  IPS:
            f.write(IP+'\n')
def CheckNetRange(domain,school):
    placeapi='http://api.webscan.cc/?action=getip&domain='
    IPS=[]
    school=school.encode('utf-8')
    with open('%s.txt'%domain,'r') as f:
        ipranges=f.read().split()
    for  iprange  in  ipranges:
        for  i  in  range(0,256):
            checkip='%s.%s.%d.0'%(iprange.split('.')[0],iprange.split('.')[1],i)
            REQURL=placeapi+checkip
            try:
                print "check ip:  %s\n"%checkip
                RES=urllib2.urlopen(REQURL,timeout=30)
                data=RES.read()
                if(data):
                    place=ast.literal_eval(data)['info'].decode('unicode_escape').encode('utf-8')
                    if  school in place:
                        print 'IP(%s) belong  to target'%checkip
                        if  checkip not  in  IPS:
                            IPS.append(checkip)
                time.sleep(1)
            except Exception as e:
                print 'Webscan Error:%s'%e
    with  open('%s.txt'%domain, "w") as f:
        for  IP  in  IPS:
            f.write(IP+'\n')
def  ip2domain(ip):
    URLS=[]
    api='http://api.webscan.cc/?action=query&ip='
    print "ip(%s) to  domian"%ip
    REQURL=api+ip
    RES=urllib2.urlopen(REQURL,timeout=30)
    data=RES.read()
    if 'null' not in data:
        data=ast.literal_eval(data)
        for  info  in  data:
            URLS.append((info["domain"]).replace('\\',''))
    return  URLS
def parse_sub_result(domain):
    with  open(domain, "r") as f:
        info = f.read()
        f.close()
    ippattern = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
    iplist = re.findall(ippattern, info)
    for ip  in  iplist:
        if  ip  not in webip:
            webip.append(ip)
def shodancrack(query):
    try:
        api = shodan.Shodan(API_KEY)
        print(query)
        print("shodan  search  start........")
        result = api.search(query)
        print ("shodan  search  over\n")
        for service in result['matches']:
            #filter_(service['ip_str'], (service['port']))
            ip=service['ip_str']
            port=service['port']
            if 'http' in service['_shodan']['module']:
                link = 'http://' + ip+ ':' + str(port)
                LINKS.append(link)
            if port ==80:
                if  ip not  in  webip:
                    webip.append(ip)
            if port == 443:
                if ip not in webip:
                    link = 'https://' + 'ip'
                    LINKS.append(link)
                    webip.append(ip)
    except Exception as e:
        print 'shodan Error: %s' % e
def getiplink():
        for  ip  in  webip:
            urls=ip2domain(ip)
            if (urls):
                for  url  in  urls:
                    if  url not in LINKS:
                         LINKS.append(url)
def saveweb(filename):
    web=[]
    with  open(filename, 'w') as  f:
        start = '''
            <html>
    <head><meta charset="UTF-8">
    <style>
a:link {color:#000000;}
a:visited {color:#00FF00;}
</style></head>
    <body>
            '''
        end = '''
            </body>
    </html>'''
        f.write(start)
        for link in LINKS:
            requset = urllib2.Request(link)
            try:
                print  "request  %s"%link
                respose=urllib2.urlopen(requset,timeout=20)
            except Exception as e:
                continue
            else:
                f.write('<a href="%s"  target="view_window">%s</a><br>\n' % (link, link))
                web.append(link)
        f.write(end)
        f.close()
        with  open("urllist.txt", 'w') as  f:
            for   link in  web:
                f.write(link+'\n')
            f.close()
if  __name__=='__main__':
    domain=sys.argv[1]
    school=sys.argv[2].decode('gbk')
    mode=sys.argv[3]
    try:
        findsub(domain)
        parse(domain)
        if(mode!='auto'):
            raw_input('enter to next step')
        CheckNetRange(domain,school)
        print "program to find net range run over"
        with  open('%s.txt'%domain,'r') as f:
            IPS=f.read().split()
            for ip  in   IPS:
                shodancrack('net:"%s/24"'%ip)
            getiplink()
            saveweb("web.html")
    except Exception  as e:
        print e
        sys.exit()
    else:
        print "script run over"
