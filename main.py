# REQUIRES python v3.8 or greater (tested on 3.8.10)
# Designed to work against RHEL target systems
import targets
import pssh_session
import argparse
import os

# Create parser (argparse)
parser = argparse.ArgumentParser()
# Add arguments
parser.add_argument('-t', '--targets', type=str, required=True,
                    help='The location of the CSV containing targets to evaluate')
parser.add_argument('-c', '--check', type=str, help='The program to evaluate for vulnerability')
parser.add_argument('-p', '--patch', type=str, help='Run in patch mode (update vulnerable machines)')
# Parse arguments
args = parser.parse_args()

# global query_prog
query_prog = args.check


def get_targets():
    if os.path.exists(args.targets):
        print("Loaded targets from " + args.targets)
    else:
        print("FNF " + args.targets + "Break here")  # normally, we quit after this w/ error
    # placeholder code that checks to see if a file exits
    # todo: add code to parse csv into a list or dict for later use


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi("Program start")  # Stuff goes to run the script
    # Sanity checks to make sure appropriate switches are being used
    if args.check and args.patch:
        print("You can't run in check and patch mode at the same time. Please run check and THEN patch your machines.")
        exit()
    if args.check:
        print("Running in check mode\nLoading targets from csv")
        get_targets()
        version = pssh_session.query_targets(query_prog)  # Get hostname/version for a computer
        print(version)  # Debug print
    if args.patch:
        pass
