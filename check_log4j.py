#!/usr/bin/env python3
# Used to pull down a copy of log4j CVEs if needed, though a copy is already in the git repo
# You will need to register for a vuldb API key and add it below
import requests, csv
import argparse
import json


# Add your personal API key here
personalApiKey = ''
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

    # Parse HTTP body as JSON
    responseJson = json.loads(response.content)


with open('log4j_issues.csv', mode ='w', newline='') as csv_file:
    fields = ['Vendor', 'version at risk', 'upgrade to', 'Vulrnablities', 'Level', 'Detail']
    csvwrite = csv.writer(csv_file)
    csvwrite.writerow(fields)
    for i in responseJson['result']:
        rows = []
        if i['software']['vendor'] == 'Apache':
            rows.append(i['software']['vendor'])


            if isinstance(i['software']['version'], list) == True:
                versions = ",".join(str(x) for x in i['software']['version'])
                rows.append(versions)
            else:
                rows.append(i['software']['version'])

            if isinstance(i['countermeasure']['upgrade']['version'], list) == True:
                up_versions = ",".join(str(x) for x in i['countermeasure']['upgrade']['version'])
                rows.append(up_versions)
            else:
                rows.append(i['countermeasure']['upgrade']['version'])
            rows.append(i['entry']['title'])
            rows.append(i['vulnerability']['risk']['name'])
            csvwrite.writerows([rows])


