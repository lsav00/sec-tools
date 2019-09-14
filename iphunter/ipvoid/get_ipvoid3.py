"""The purpose of version 3 is to add the code to request the APIVoid info instead of having to paste it below. 1 way to accomplish this take is to save the output as a json file and use python to open the file. Instead of creating a json file, let's see if python can do the request and save the response into a variable and then parse the variable ==> It worked!."""

import requests
headers = {"user-agent": "Mozilla/5.0"}
URL="https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key=******keygoeshere******&ip=200.140.194.111"
session = requests.session()
r = requests.post(URL)
x=(r.text)

input("Request is done. Hit enter to view the response")
print(x)

input("STOP!")


"""
objective: parse apivoid output (json format) with python and print only true detection engines
solution: used get on the detected key and checked if "True"
POC: this script prints the engines that detected the IP True
setup: use requests and apivoid key and ip to search and print to terminal. copy the JSON into x's assignment below (line 14). imported json into splunk to read the json easier 
"""

import json

# parse "x":
# assign all of "x" to "y" but in a "json loads" format
y = json.loads(x)

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
for f in e:
	j=e[f]
	j1=str(j.get('detected'))
	if j1=="True":
	#print the engines that detected the IP as malicious
		print(j.get('engine'))

print("Detection Rate:", c)
print("Detections:", d)

"""for analysis purposes, I think we're good with the:
1. Number of detections 
2. Detection rate percentage, and
3. The list of engines that detected positive
"""
