"""
example ip with threat hits: 181.143.53.227
"""


import requests
import json
import os
import time
import re

print("IP REPORT")
print("IP REPORT contains summary of threat intel from IPVoid, AbuseIPDB, OTXAlienVault, VirusTotal")
IP=input("enter IP you wish to search")
print(IP)

#VIRUSTOTAL
headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "gzip,  My Python requests library example client or username"
  }
params = {'apikey': '*********apikey-goeshere********', 'resource': IP}
response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
json_response = response.json()

xcc1=[]

#print(json_response)
imp=json_response.get('response_code')
if imp==0:
	vtresult=("Not in VT database")
	print("Not in VT database")
else:
	a=json_response.get('positives')
	b=json_response.get('total')
	#print(a)
	#print(b)
	if a==0:
		vtresult=""
		vtresult=str(a) + "/" + str(b)
		print("VT:", a, "/", b)
	else:
		vtresult=""
		vtresult=str(a) + "/" + str(b)
		c=json_response.get('scans')
		#print(type(c)) # c is a dict
		for xcc in c:
			#print(xcc)
			#print(c[xcc])
			mmm=c[xcc]
			nnn=mmm.get('detected')
			if nnn==True:
				xcc1.append(xcc)
				print(xcc)
		#input("checkit2")
		#if j3=="True":
		#print the engines that detected the P as malicious
		#	ff1=(j.get('engine'))
		#	ff.append(ff1)



#ALIENVAULT
avline="alien3.py -i "
avline = avline + IP
avline = avline + " > avoutput.txt"
		
os.system(avline)
time.sleep(.5)

#replace single quotes with double quotes
with open('avoutput.txt', 'r') as myfile:
	with open('avoutput1.json', 'w') as newfile:
		for x in myfile:
			x=x.replace("\'", "\"")
			x=x.replace("None", "\"None\"")
			x=x.replace("False", "\"False\"")
			x=x.replace("True", "\"True\"")
			x=x.replace("\"\"None\"\"", "\"None\"")
			#print(x)
			newfile.write(x)
			#input("stopl")

time.sleep(1)

print("OTXAlienVault")

with open('avoutput1.json', 'r') as myfile:
	if len(myfile.readlines()) != 0:
		myfile.seek(0)		
		data = json.load(myfile)

a=data['general']
b=a['sections']
city=a['city']
areacode=a['area_code']
e=a['pulse_info']
f=e['count']
g=e['pulses']
m=data['url_list']
m1=m['url_list']
#try:
#	m2=m1[0]
#	m3=m2.get('url')
#	m4=m2.get('hostname')
#	print("url:", m3)
#except:
#	print("")
p=data['geo']
q=p.get('country_name')
asn=p.get('asn')
ct=0


print("-Country:", q)
print("-City:", city)
#print("-Area Code:", d)
#print("-ASN:", r)
#print("-Number of Detections:", len(g))




#IPVoid

headers = {"user-agent": "Mozilla/5.0"}
URL="https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key=*********APIKEY-GOESHERE***********&ip="
URL = URL + IP
session = requests.session()
r = requests.post(URL)
r1=r.text


# parse "x":
# assign all of "x" to "y" but in a "json loads" format
y = json.loads(r1)

# assign the "data" of "y" to "z". If you print "z" you will have the same as "x", because all of "x" is contained in "data".
z=y['data']

# assign the "report" data of "z" to "a". We're still going to see most of "x" except the "data" value
a=z['report']

# same as above, we're still trying to parse through the parent fields and get to the important info, which is the engines that detected the IP as malicious
b=a['blacklists']

#while we're drilling down, let's grab the "detection rate"...I believe the detection rate is the percentage of engines that detected the IP as malicious vs. the engines that did not. The higher the percentage, the more likely the IP is malicious.
c=b['detection_rate']

#... and the number of detections.
d=b['detections']

#now we've drilled down far enough, we can assign all the engines (both engines that detected the IP as malicious and the engines with no detections)
e=b['engines']

#the following "for" statement iterates through all the engines stored in "e". Each of the engines values also contain the "detected" value of "true" or "false".
ff=[]
for f in e:
	j=e[f]
	j1=str(j.get('detected'))
	if j1=="True":
	#print the engines that detected the IP as malicious
		ff1=(j.get('engine'))
		ff.append(ff1)


#AbuseIPDB
headers = {"user-agent": "Mozilla/5.0"}
URL="https://www.abuseipdb.com/check/"
URL+=IP
URL+="/"
session = requests.session()
r = requests.post(URL)
abu=(r.text)

#regex AbuseIPDB web
abu4=abu.replace("\n", "")
abu5=abu4.replace("\"", "")
#print(abu4)
#input("pop")
poppers=re.findall("flag.\w+.\w+..\w+", abu5)[0]
poppers2=poppers[14:]
poppers3=re.findall(">City<.\w+..\w+.\w+.?.?\w+", abu5)[0]
poppers4=poppers3[14:]

letters = re.findall('This.*%<\/b', abu4)[0]
print(letters)
#print(abu4)
input("pop")
letter1=letters.replace("<b>", "")
letter2=letter1.replace("</b>", "")
letter3=letter2
print(letter2)
input("MO")

letters=re.findall('<th>ISP.*<\/td><\/tr><tr><th>Usage', abu4)
for letter in letters:
	letter1=letter.replace("<th>ISP</th><td>", "")
	letter7=letter1.replace("</td></tr><tr><th>Usage", "")
	print(letter7)
	letter4=letter7
	input("MO")
	



#REPORT
print("#" * 100)
print("#" * 100)
print("#" * 100)
print()

#####################

print("On ___, the following threat intel was discovered for IP " + IP + ":")

print("AbuseIPDB:", "(", poppers2, ",", poppers4, ")", "ISP:", letter4)
print("-", letter3[:-3])
print("IPVoid:")
print("-", d, "blacklists", "(", c, "detection rate).")
print("OTXAlienVault:", "(", q, ",", city, ",", "ASN:", asn, ")")
print("-", len(g), "Pulse Detections")
print("VirusTotal")
print("-Score:", vtresult)
print()


print("#" * 100)
print("Appendix-IPVoid")
print("#" * 100)
for pp in ff:
	print(pp)
	
	
print("#" * 100)
print("Appendix-AlienVault")
print("#" * 100)
print("-City:", city)
print("-Area Code:", areacode)
print("-ASN:", asn)
for h in g:
	ct+=1
	i=h.get('name')
	j=h.get('author')
	k=j.get('username')
	print("--" + str(ct)+ ")", i, ":", k)
	
print()
print("#" * 100)
print("Appendix-VirusTotal")
print("#" * 100)
for xcca in xcc1:
	print(xcca)
	
print()
print("#" * 100)
print("Appendix-AbuseIPDB")
print("#" * 100)
