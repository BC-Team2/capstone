#!/usr/bin/env python3
"""Application for evaluating app dynamics for log4j vulnerabilities. Contains the main/handler functions"""
# REQUIRES python v3.8 or greater (tested on 3.8.10)
# Designed to work against RHEL target systems
# Lead architect and developer - Josh Parmely https://www.linkedin.com/in/jparmely/
import pssh_session
import logging
import argparse
import os
import csv
import time
import getpass
from datetime import datetime

# This is the version that is not vulnerable, per
# https://docs.appdynamics.com/display/PAA/Security+Advisory%3A+Apache+Log4j+Vulnerability
# We should update any client that is LESS THAN this version number
NON_VULNERABLE_VERSION = '21.11.2'
# Program to evaluate (of which we want the version number for, and to upgrade if needed)
QUERY_PROG = "appdynamics-machine-agent"
# Specify SSH port here as str, if you're using nonstandard ports
SSH_PORT = '22'

# Create parser (argparse)
parser = argparse.ArgumentParser()
# Add arguments: -t is mandatory
parser.add_argument('-t', '--targets', type=str, required=True,
                    help='The location of the CSV containing targets to evaluate')
parser.add_argument('-i', '--key', type=str,
                    help='The FULL path to the SSH private key for a user with sufficient privileges')
# If '-c' is used, it will return true (user is running script in check ONLY mode)
parser.add_argument('-c', '--check', action='store_true', help='Check mode (No remediation)')
parser.add_argument('-u', '--user', type=str, help='The user to create the ssh session as, if different than current')
parser.add_argument('-p', '--password', action='store_true',
                    help='If your SSH key requires a password, enable this switch')
# Parse arguments
args = parser.parse_args()

# Create and configure logger
logging.basicConfig(filename="log.log", format='%(asctime)s:%(levelname)s:%(name)s:%(message)s', filemode='w')

# Creating an object
logger = logging.getLogger()

# Setting the threshold of logger to INFO. For more verbosity for paramiko, switch to DEBUG.
logger.setLevel(logging.INFO)


def get_targets():
    """Pulls the target list out of the csv supplied at program start and returns a list"""
    tlist = []
    # If a file exists at the location passed, load the contents, then append each line to a list
    logger.info(f'Trying to load target list from {args.targets}')
    if os.path.exists(args.targets):
        with open(args.targets, 'r') as infile:
            csvin = csv.reader(infile, delimiter=',')
            for line in csvin:
                # Strip out the white space for each line in the CSV to make sure it remains a valid IP
                trim = (field.strip() for field in line)
                tlist.append(trim)
        print("Loaded targets from " + args.targets)
        logger.info(f'Targets loaded from {args.targets}')
        return tlist
    # If the file is not found, give error and exit.
    else:
        print("File not found: " + args.targets + "\nExiting")  # normally, we quit after this w/ error
        logger.critical("File not found: " + args.targets + "\nExiting")
        exit(2)


def check_output_dir():
    """Make sure we can write to our output directory"""
    if not os.path.isdir('output'):
        os.mkdir('output')
        logger.info('Output directory not found. Creating.')


def build_remediation_list(scan_list):
    """Accepts the results of the vulnerability check as a list, parses out targets by status
    and returns that list"""
    remediation_list = []
    failed_list = []
    non_vulnerable_list = []
    logger.info('Remediation process starting')
    # Finds which items are vulnerable, which had errors, and the rest (non-vulnerable)
    for i in scan_list:
        if 'Failed' in i[1] or 'Error' in i[1] or 'Connection failed' in i[1]:
            failed_list.append(i)
        elif i[2] == 'Version VULNERABLE':
            remediation_list.append(i[0])
        else:
            non_vulnerable_list.append(i)
    return remediation_list, non_vulnerable_list, failed_list


def print_final_results(non_vulnerable_list, failed_list, updated_list):
    """Prints out systems by status to the console"""
    print('\n\n*****FINAL REPORT*****')
    print('\nThe following systems were not vulnerable originally:')
    print('Name\t\tVersion')
    for i in non_vulnerable_list:
        print(f'{i[0]}\t{i[1]}')
    print('\nThe following systems could not be connected to, or appdynamics was not found:')
    print('Name\t\tVersion')
    for i in failed_list:
        print(f'{i[0]}\t{i[1]}')
    print('\nThe following systems had attempts made to update them to the current repo version. See status:')
    print('Name\t\tVersion')
    for i in updated_list:
        print(f'{i[0]}\t{i[1]}\n')


def export_to_csv(non_vulnerable_list, failed_list, updated_list, outfile):
    """Exports final results to csv"""
    header = ['address', 'version', 'final status']
    with open(outfile, 'w', newline='') as o:  # Open the outfile, as writable (overwrite each time)
        writer = csv.writer(o)
        writer.writerow(header)
        for i in non_vulnerable_list:
            writer.writerow(i)
        for i in failed_list:
            writer.writerow(i)
        for i in updated_list:
            writer.writerow(i)
    print(f'\nResults written to {outfile}')


def export_to_csv_short(export_list, outfile):
    """Exports first stage/check only results to csv"""
    header = ['address', 'version', 'final status']
    with open(outfile, 'w', newline='') as o:  # Open the outfile, as writable (overwrite each time)
        writer = csv.writer(o)
        writer.writerow(header)
        for i in export_list:
            writer.writerow(i)
    print(f'\nResults written to {outfile}')


def check_for_password():
    """If the password switch is used, collect password from user"""
    if args.password:
        print('Enter the password for the target account. Input will be masked.')
        user_pass = getpass.getpass()
        logger.info('User provided password for connection')
        return user_pass


def build_params():
    """Build a list of parameters based on provided switches to pass to paramiko"""
    # Create dict with port number, which is always present
    params = {
        'port': SSH_PORT
    }
    # Update the dict with new key:value pairs depending on if a parameter is given by user
    if args.user:
        params.update({'username': args.user})
    if args.password:
        params.update({'password': user_password})
    if args.key:
        params.update({'key_filename': args.key})
    return params


def banner():
    """Displays the opening banner for the program"""
    print('*' * 20)
    print('Welcome to ADCheck - A program to evaluate App Dynamics installs for log4j vulnerabilities.\n')


if __name__ == '__main__':
    """Main function (call other functions from here)"""
    banner()
    # See if the user wants to pass a password and handle collection
    # If the folder where our output (csv files) doesn't exist, create one
    check_output_dir()
    user_password = check_for_password()
    # Build connection parameters to be used by paramiko
    connection_params = build_params()
    # If check only is on, print to console.
    if args.check:
        print("Running in check ONLY mode - No remediation will be done\n")
    logger.info(f'Evaluating for  {QUERY_PROG}  greater than or equal to version {NON_VULNERABLE_VERSION}')
    print('Evaluating for ' + QUERY_PROG + ' greater than or equal to version ' + NON_VULNERABLE_VERSION)
    print('Loading targets from ' + args.targets + '...')
    # Get the list of clients to work on
    target_list = get_targets()
    # 5 second safety net before we touch any systems
    print('Waiting 5 seconds before connecting to systems. Ctrl+C to break')
    time.sleep(5)
    # Check initial list of targets for vulnerability
    scan_results = pssh_session.get_vulnerability_status_ssh(target_list, args.key, connection_params)
    # Export results in case the user wants to run a diff between original state and after remediation
    export_to_csv_short(scan_results, f"output/stage1_results_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S.csv')}")
    if args.check:
        # No remediation done with check switch enabled, exit here
        exit(0)

    # Start Remediation Process
    # Create a list of targets that are vulnerable and need updating
    remediation_list, non_vulnerable_list, failed_list = build_remediation_list(scan_results)
    print('\n---Starting remediation process---\n')
    # 5 second safety net before we touch any systems
    print('Waiting 5 seconds before connecting to systems. Ctrl+C to break')
    time.sleep(5)
    # Attempt to update systems and return the results
    updated_list = pssh_session.remediate_targets(remediation_list, args.key, connection_params)
    # Print out results for user
    print_final_results(non_vulnerable_list, failed_list, updated_list)
    # Export results to CSV file
    export_to_csv(non_vulnerable_list, failed_list, updated_list,
                  f"output/final_results_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S.csv')}")
