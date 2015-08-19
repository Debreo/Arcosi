#!/usr/bin/env python
# ArcOSI 
# Scrapes OSINT data for import into ESM via CEF/Syslog
# gregcmartin at gmail.com
# http://infosec20.blogspot.com
#
#----------------------------------------------------------------------------
# The MIT License
#
#Copyright 2011 Greg C. Martin
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.
#
import urllib2, re, socket, sys, time, os, string
import ConfigParser, subprocess 
from optparse import OptionParser

#Config parser
Config = ConfigParser.ConfigParser()
SECTIONS = ['PROXY','IPSOURCES','DOMAINSOURCES','IPWHITELIST','DOMAINWHITELIST'] #Keep ordering

#Command line options 
VERSION = "v3.0"
USAGE = """Usage: arcosi.py [Options] 

A configuration file with the following syntax could be provided:
    [PROXY]
    enabled = no
    host = proxy.localhost
    port = 3128
    user = none
    pass = none

    [IPSOURCES]
    url1 = http://www.mtc.sri.com/live_data/attackers/
    url2 = http://intel.martincyber.com/ip

    [DOMAINSOURCES]
    url1 = https://secure.mayhemiclabs.com/malhosts/malhosts.txt
    url2 = https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist

    [DOMAINWHITELIST]
    url1 = www.malwaredomainlist.com
    url2 = sites.googlegroups.com

    [IPWHITELIST]
    ip1 = 127.0.0.1
"""
parser = OptionParser(USAGE)
parser.add_option("-c",
                  action="store", type="string", dest="config",
                  default = "",
                  help="load configuration file")
parser.add_option("-v",
                  action="store_true", dest="version",
                  default=False,
                  help="show version")
parser.add_option("-d",
                  action="store_true", dest="debug",
                  default=False,
                  help="show debug information")
parser.add_option("-p",
                  action="store", dest="port",
                  default=False,
                  help="specify custom udp destination port")

(options, args) = parser.parse_args()

if options.version:
    print "ArcOSI", VERSION
    sys.exit()

if options.port:
    dport = options.port
    dport = int(dport)
else:
    dport = 514

if (len(args) != 0):
    parser.print_help()
    sys.exit()


#Default configuration
CONFIG={}

CONFIG['FACILITY'] = {
        'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
        'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
        'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
        'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
        'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

CONFIG['LEVEL'] = {
        'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
        'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

#Sections which can be override by config file
CONFIG['PROXY'] = {
'enabled' : 'no',
'host' : "proxy.localhost",
'user' : 'none',
'pass' : 'none',
'port' : '3128'
}

CONFIG['IPSOURCES'] = [
		'http://intel.martincyber.com/ip/',
		'https://reputation.alienvault.com/reputation.generic',
		'http://www.mtc.sri.com/live_data/attackers/', 
		'http://isc.sans.edu/reports.html',
		'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist',
		'https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist', 
		'http://www.projecthoneypot.org/list_of_ips.php',
                'http://amada.abuse.ch/palevotracker.php',
                'http://www.blocklist.de/lists/ssh.txt',
                'https://www.openbl.org/lists/base.txt',
		'http://www.nothink.org/blacklist/blacklist_malware_http.txt',
		'http://www.malwaregroup.com/ipaddresses',
		'http://www.ciarmy.com/list/ci-badguys.txt',
		'http://rules.emergingthreats.net/blockrules/rbn-malvertisers-ips.txt',
]


CONFIG['DOMAINSOURCES'] = [ 
		'http://www.nothink.org/blacklist/blacklist_malware_dns.txt',
		'https://secure.mayhemiclabs.com/malhosts/malhosts.txt',
		'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist',
		'https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist',
		'http://mirror1.malwaredomains.com/files/BOOT',
		'http://www.malwaredomainlist.com/hostslist/hosts.txt',
		'http://www.malware.com.br/cgi/submit?action=list',
                'http://amada.abuse.ch/palevotracker.php',
		'http://www.malwarepatrol.net/cgi/submit?action=list',
		'http://www.malwaregroup.com/domains',
]
CONFIG['IPWHITELIST'] = [] 
CONFIG['DOMAINWHITELIST'] = [] 

#Override default configuration with config file content if provided
if options.config != "":
    if os.access(options.config,os.R_OK):
        Config.read(options.config)
        
        for section in Config.sections():
            if options.debug:
                print "Parsing", section
            if section not in SECTIONS:
                continue
            
            if section != SECTIONS[0]:
                CONFIG[section] = []
                for option,value in Config.items(section):
                    if options.debug:
                        print "    ", value
                    CONFIG[section].append(value)
            else:
                # Special handling for PROXY
                CONFIG[section]={}
                for option,value in Config.items(section):
                    if options.debug:
                        print "    %s = %s" % (option,value)
                    CONFIG[section][option]=value
    else:
        print "Unable to load configuration file:", options.config
        print "Using default configuration"


# Set Global Timeout
socket.setdefaulttimeout(30)

#Set Regex
ip_regex = re.compile(r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
dom_regex = re.compile(r'([\d\w.][-\d\w.]{0,253}[\d\w.]+\.)+(AC|AD|AE|AERO|AF|AG|AI|AL|AM|AN|AO|AQ|AR|ARPA|AS|ASIA|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BIZ|BJ|BM|BN|BO|BR|BS|BT|BV|BW|BY|BZ|CA|CAT|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|COM|COOP|CR|CU|CV|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EDU|EE|EG|ER|ES|ET|EU|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GOV|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|INFO|INT|IO|IQ|IR|IS|IT|JE|JM|JO|JOBS|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MG|MH|MIL|MK|ML|MM|MN|MO|MOBI|MP|MQ|MR|MS|MT|MU|MUSEUM|MV|MW|MX|MY|MZ|NA|NAME|NC|NET|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|ORG|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PRO|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|SY|SZ|TC|TD|TEL|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TP|TR|TRAVEL|TT|TV|TW|TZ|UA|UG|UK|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|XN|XN|XN|XN|XN|XN|XN|XN|XN|XN|XN|YE|YT|YU|ZA|ZM|ZW)', re.IGNORECASE)
comment_regex = re.compile ("#.*?\n")
comment2_regex = re.compile ("//.*?\n")


# Simple HTTP(S) Scraper
def scrape(url, regex):
		try:
			content = urllib2.urlopen(url).read()
			print '\nGrabbing list from: '+url+'\n'
			time.sleep(1)
                        results = re.sub(comment_regex,"", content)
                        results = re.sub(comment2_regex,"", results)
                        results = re.findall(regex, results)
			return results
		except:
			print 'Failed connection to: '+url+' skipping...'
			print '\n'
			time.sleep(1)
			return 'failed'


def syslog(message, level=CONFIG['LEVEL']['notice'], facility=CONFIG['FACILITY']['daemon'], host='localhost', port=512):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data = '<%d>%s' % (level + facility*8, message)
        sock.sendto(data, (host, port))
        sock.close()


def getosint():
    group = []
    for source in group:
	#for source in CONFIG[SECTIONS[2]]:
        op = scrape(source, dom_regex)
        if op != 'failed':
            for i in op:
                domain = i[0]+i[1]
                #Filter whitelisted results 
                if str(CONFIG['DOMAINWHITELIST']).find(domain) != -1:
                    if options.debug:
                        print "Skipping domain %s due to whitelisting" % domain
                    continue
                print 'Known malicious domain: %s' % (domain)
               
		#######################	
		#######################################################################################
		## convert data to the xml upload format demanded by SOLR and save locally 
		## https://cwiki.apache.org/confluence/display/solr/Uploading+Data+With+index+Handlers
		#######################################################################################
		#######################

		domain_doc = open("./domain_xmls/"+domain+".xml", "w")
		domain_doc.write("<add><doc><field name=\"description\">malicious domain</field><field name=\"Domain Name\">"+domain+"</field><field name=\"source\">"+source+"</field></doc></add>")
		domain_doc.close
		
		time.sleep(.02)
                
    for source in CONFIG[SECTIONS[1]]:
        op = scrape(source, ip_regex)
        if op != 'failed':
            for i in op:
                ip = i[0]+'.'+i[1]+'.'+i[2]+'.'+i[3]
                #Filter whitelisted results 
                if str(CONFIG['IPWHITELIST']).find(ip) != -1:
                    if options.debug:
                        print "Skipping ip %s due to whitelisting" % ip
                    continue                
                print 'Known malicious IP: %s' % (ip)


		########################                
		#######################################################################################
		## make API call to san server for info on the IP & parse the response using regex 
		#######################################################################################
		########################


		ip_doc = open("./ip_xmls/"+ip+".xml", "w")
		san_response = urllib2.urlopen("https://isc.sans.edu/api/ip/"+ip).read() 
		field_search = re.search('<ip><ip>(.*)</ip><paddedip>(.*)</paddedip><count>(.*)</count><attacks>(.*)</attacks><maxdate>(.*)</maxdate><mindate>(.*)</mindate><updated>(.*)</updated><comment>(.*)</comment><asabusecontact>(.*)</asabusecontact><as>(.*)</as><asname>(.*)</asname><ascountry>(.*)</ascountry><assize>(.*)</assize><network>(.*)</network></ip>', san_response)


		san_ip=field_search.group(1) 
		san_paddedip=field_search.group(2) 
		san_count=field_search.group(3)
		san_attacks=field_search.group(4) 
		san_maxdate=field_search.group(5) 
		san_mindate=field_search.group(6) 
		san_updated=field_search.group(7) 
		san_comment=field_search.group(8) 
		san_asabusecontact=field_search.group(9) 
		san_as=field_search.group(10) 
		san_asname=field_search.group(11) 
		san_ascountry=field_search.group(12) 
		san_assize=field_search.group(13) 
		san_network=field_search.group(14)	

		################################################
		## rewrite the xml fields to SOLR upload specs
		################################################

		ip_text="<add><doc><field name=\"ip\">"+san_ip+"</field><field name=\"padded ip\">"+san_paddedip+"</field><field name=\"count\">"+san_count+"</field><field name=\"attacks\">"+san_attacks+"</field><field name=\"oldest date\">"+san_maxdate+"</field><field name=\"newest date\">"+san_mindate+"</field><field name=\"updated\">"+san_updated+"</field><field name=\"comment\">"+san_comment+"</field><field name=\"AS abuse contact\">"+san_asabusecontact+"</field><field name=\"AS\">"+san_as+"</field><field name=\"asname\">"+san_asname+"</field><field name=\"AS country\">"+san_ascountry+"</field><field name=\"AS size\">"+san_assize+"</field><field name=\"network\">"+san_network+"</field></doc></add>"
		
		#save file locally
		ip_doc.write(ip_text)
		ip_doc.close() 

time.sleep(.02)
		
#Main

#Check/Initialize  Config
if CONFIG['PROXY']['enabled'] != 'no':
	proxy_support = urllib2.ProxyHandler({\
             "http"  : "http://%(user)s:%(pass)s@%(host)s:%(port)s" % CONFIG['PROXY'],
             "https" : "http://%(user)s:%(pass)s@%(host)s:%(port)s" % CONFIG['PROXY']})
	opener = urllib2.build_opener(proxy_support, urllib2.HTTPHandler)
	urllib2.install_opener(opener)

# Go scraper
getosint()
