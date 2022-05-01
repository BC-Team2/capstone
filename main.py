#!/usr/bin/python3
# REQUIRES python v3.8 or greater (tested on 3.8.10)
# Designed to work against RHEL target systems
import pssh_session
import argparse
import os
import csv
import time

# This is the version that is not vulnerable, per
# https://docs.appdynamics.com/display/PAA/Security+Advisory%3A+Apache+Log4j+Vulnerability
# We should update any client that is LESS THAN this version number
NON_VULNERABLE_VERSION = '21.11.2'
# Program to run (of which we want the version number for)
QUERY_PROG = "vim"

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
# Parse arguments
args = parser.parse_args()


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


if __name__ == '__main__':
    """Main function (call other functions from here)"""
    # If check only is on, says so
    if args.check:
        print("Running in check ONLY mode\n")
    print('Loading targets from ' + args.targets + '...')
    # Get the list of clients to work on
    target_list = get_targets()
    # 5 second safety net before we touch any systems
    print('Waiting 5 seconds before connecting to systems. Ctrl+c to break')
    time.sleep(5)
    pssh_session.connect_to_targets(target_list, args.key)
    # Debug code - prints the list of clients
    # for i in target_list:
    #     print(i)
    ###
    # TODO: The 'get version' code is probably going to change once we run multiple machines
    # version = pssh_session.query_targets(QUERY_PROG)  # Get hostname/version for a computer
    # print(version)  # Debug print
