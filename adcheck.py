#!/usr/bin/python3
# REQUIRES python v3.8 or greater (tested on 3.8.10)
# Designed to work against RHEL target systems
import pssh_session
import logging
import argparse
import os
import csv
import time

# This is the version that is not vulnerable, per
# https://docs.appdynamics.com/display/PAA/Security+Advisory%3A+Apache+Log4j+Vulnerability
# We should update any client that is LESS THAN this version number
NON_VULNERABLE_VERSION = '21.11.2'
# Program to run (of which we want the version number for)
QUERY_PROG = "appdynamics-machine-agent"

# Create parser (argparse)
parser = argparse.ArgumentParser()
# Add arguments
# -t is mandatory
parser.add_argument('-t', '--targets', type=str, required=True,
                    help='The location of the CSV containing targets to evaluate')
parser.add_argument('-i', '--key', type=str, required=True,
                    help='The FULL path to the SSH private key for a user with sufficient privileges')
# If '-c' is used, it will return true (user is running script in check ONLY mode)
parser.add_argument('-c', '--check', action='store_true', help='The program to evaluate for vulnerability')
parser.add_argument('-u', '--user', type=str, help='The user to create the ssh session as, if different than the '
                                                   'currently logged in use')
# Parse arguments
args = parser.parse_args()

# Create and configure logger
logging.basicConfig(filename="log.log", format='%(asctime)s:%(levelname)s:%(name)s:%(message)s', filemode='w')

# Creating an object
logger = logging.getLogger()

# Setting the threshold of logger to DEBUG
logger.setLevel(logging.DEBUG)


def get_targets():
    """Pulls the target list out of the csv supplied at program start and returns a list"""
    tlist = []
    # If a file exists at the location passed, load the contents, then append each line to a list
    if os.path.exists(args.targets):
        with open(args.targets, 'r') as infile:
            csvin = csv.reader(infile, delimiter=',')
            for line in csvin:
                tlist.append(line)
        print("Loaded targets from " + args.targets)
        return tlist
    # If the file is not found, give error and exit.
    else:
        print("File not found: " + args.targets + "\nExiting")  # normally, we quit after this w/ error
        exit(2)


def build_remediation_list(scan_list):
    """Accepts the results of the vulnerability check as a list, parses out targets by status
    and returns that list"""
    remediation_list = []
    failed_list = []
    non_vulnerable_list = []
    for i in scan_list:
        if 'Failed' in i[1] or 'Error' in i[1]:
            failed_list.append(i)
        elif i[2] == 'Version VULNERABLE':
            remediation_list.append(i[0])
        else:
            non_vulnerable_list.append(i)
    return remediation_list, non_vulnerable_list, failed_list


if __name__ == '__main__':
    """Main function (call other functions from here)"""
    # If check only is on, says so. We're not using this? Remove.
    if args.check:
        print("Running in check ONLY mode\n")
        logger.info(f'Evaluating for  {QUERY_PROG}  greater than or equal to version {NON_VULNERABLE_VERSION}')
    print('Evaluating for ' + QUERY_PROG + ' greater than or equal to version ' + NON_VULNERABLE_VERSION)
    print('Loading targets from ' + args.targets + '...')
    # Get the list of clients to work on
    logger.info(f'Trying to load target list from {args.targets}')
    target_list = get_targets()
    logger.info(f'Targets loaded from {args.targets}')
    # 5 second safety net before we touch any systems
    print('Waiting 5 seconds before connecting to systems. Ctrl+c to break')
    time.sleep(5)
    # Check initial list of targets for vulnerability
    scan_results = pssh_session.get_vulnerability_status_ssh(target_list, args.key)
    # Create a list of targets that are vulnerable and need updating
    remediation_list = build_remediation_list(scan_results)

    # TODO: Finish remediation functions
    # TODO: Run a second scan on vulnerable targets to make sure the updates happened appropriately
    # TODO: Output first vuln scan to csv. Then final results with all targets to CSV
