#! /usr/bin/python3
# jschump
import subprocess, re, csv

# Default path for appdynamics. Change this if your location is different.
APP_DYN_PATH = '/opt/appdynamics/'


def check_log4jcore(client):
    """Check for the presence of the log4j-core file in the appdynamics directory.
    Parse out the version number and pass the version number to a version lookup function"""
    lscheck1 = stdin, stdout, stderr = client.exec_command('ls /opt/appdynamics/machine-agent/')
    lscheck2 = stdout.read().decode('utf8')
    # TODO: Error checking for abnormal ls results

    core_results = stdin, stdout, stderr = client.exec_command('find ' + APP_DYN_PATH + ' -name "log4j-core*"')
    core_results_decoded = stdout.read().decode('utf8')

    if re.search("-([0-9]+).(\d*).(\d*)", core_results_decoded):
        check_ver = re.search("-([0-9]+).(\d*).(\d*)", core_results_decoded)
        check = check_ver.group(0)
        output = (check[1:])
        evaluate_log4jcore(output)


def evaluate_log4jcore(output):
    """Read in a CSV of CVSS ratings for log4j. Find which level of vulnerability the version in our instance has"""
    with open('log4j_issues.csv', 'r') as testfile:
        read = csv.reader(testfile, delimiter=',')
        # For each row (CVE) in our CVSS data, compare it to the version on this client and print out the results
        for row in read:
            if row[4] == 'high':
                test = row[1].split(",")
                for v_risk in test:
                    if v_risk == output:
                        print('CVSS Rating: HIGH')
            elif row[4] == 'medium':
                test = row[1].split(",")
                for v_risk in test:
                    if v_risk == output:
                        print('CVSS Rating: Medium')
