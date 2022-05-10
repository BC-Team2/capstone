#!/usr/bin/env python3
import requests, csv
import argparse
import json


# Add your personal API key here
personalApiKey = 'api key'
#
# # Set HTTP Header
userAgent = 'VulDB API Advanced Python Demo Agent'
headers = {'User-Agent': userAgent, 'X-VulDB-ApiKey': personalApiKey}
#
# # URL VulDB endpoint
url = 'https://vuldb.com/?api'

postData =  {'search': 'log4j', 'details': 1}


# # Get API response
response = requests.post(url, headers=headers, data=postData)
#
# # Display result if evertything went OK
if response.status_code == 200:
#
    # Parse HTTP body as JSON
    responseJson = json.loads(response.content)
   # print(responseJson)

    # Output
#  print(responseJson) grabs full info on pulled data
    print(responseJson)
with open('location of where you want to save your csv file', mode ='w') as csv_file:
    fields = ['Vendor', 'version at risk', 'upgrade to', 'Vulrnablities', 'Level', 'Detail']
    csvwrite = csv.writer(csv_file)
    csvwrite.writerow(fields)
    for i in responseJson['result']:
        rows = []
        if i['software']['vendor'] == 'Apache':
            rows.append(i['software']['vendor'])
            rows.append(i['software']['version'])
            rows.append(i['countermeasure']['upgrade']['version'])
            rows.append(i['entry']['title'])
            rows.append(i['vulnerability']['risk']['name'])
            csvwrite.writerows([rows])


