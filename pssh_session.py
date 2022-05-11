import re
import subprocess
import sys
import paramiko
from paramiko import SSHClient, AutoAddPolicy

import main
from main import QUERY_PROG


def connect_to_targets(targets, key):
    """POC for connecting to a remote machine via ssh and running a command, returning the output to console"""
    client = SSHClient()
    # client.load_host_keys(filename=ssh_key)
    client.set_missing_host_key_policy(AutoAddPolicy)
    # client.load_system_host_keys()
    # Iterate through the targets list, connecting and performing an action.
    # Nested loop because we end up with a list of lists for this function
    for t in targets:
        for tar in t:
            print('Trying ' + tar)
            try:
                client.connect(tar, username='jparmrat', key_filename=key)
            except paramiko.SSHException as e:
                print(e)
                print('There was an error connecting to the server (SSH KEY). Exiting')
                # TODO: in theory, we should be able to keep this from happening, requiring an exit
                sys.exit(1)
            # If we connected successfully, proceed to evaluate the program version and report findings via console
            print("Connected to " + tar + ", running checks")
            # Check installed RPMs. Grep for the program we're looking for
            stdin, stdout, stderr = client.exec_command('rpm -qa | grep ' + main.QUERY_PROG)
            if stdout.channel.recv_exit_status() == 0:
                rpm_output = stdout.read().decode("utf8")
                # If that output is not blank (we found it)
                if rpm_output != '':
                    print('Found: ' + rpm_output)
                    # Regex to get the version number from the package listing
                    app_ver_re = re.search("appdynamics-machine-agent-(.*).x", rpm_output)
                    app_version = app_ver_re.group(1)
                    # Call function to evaluate whether this version is vulnerable
                    vuln_status = eval_version(app_version)
                    print(vuln_status)
                else:
                    print('Client not found')
                # Prints The Standard Output in Human Readable Format
                # Implement logging feature around here.
            else:
                print(f'ERROR: {stderr.read().decode("utf8")}')
                # Prints The Standard Error (If any) in Human Readable Format
            # Close out all of these files to clean up
            stdin.close()
            stdout.close()
            stderr.close()
            client.close()


def eval_version(ver):
    """Function that breaks down version numbers, separated by periods. Evaluates to three places"""
    check_ver = re.search("(\d*).(\d*).(\d*).(\d*)", ver)
    nonvuln_split = main.NON_VULNERABLE_VERSION.split('.')
    # Sees if each section of the version number (major, sub version, etc.) is less than the nonvulnerable version, left
    # to right, in sequence. We assume that if any place is less than the non-vulnerable version, the installed
    # version is inferior and needs to be updated. Ex. 21.10 fails this check, and no further
    # eval is needed
    if int(check_ver.group(1)) >= int(nonvuln_split[0]):
        return 'Version not vulnerable'
    elif int(check_ver.group(1)) == int(nonvuln_split[0]) and (int(check_ver.group(1)) >= int(nonvuln_split[0])):
        return 'Version not vulnerable'
    elif int(check_ver.group(1)) == int(nonvuln_split[0]) and (int(check_ver.group(1)) >= int(nonvuln_split[0])) and \
            (int(check_ver.group(2)) >= int(nonvuln_split[1])):
        return 'Version not vulnerable'
    else:
        return 'Version VULNERABLE'


# todo: the command(s) that actually get run should be a separate function. Determine how to pass the existing
#  session to a function
# todo: Update code to make sure we can make a connection, and report why (exception text) to
#  the user. Export this list as a csv since they will get skipped, and the user needs to fix the auth issue and run
#  them again.
# todo: longer term - we need to log connection success/fail, and the console output for what happens during version
#  check and remediation


def install_repo():
    pass  # Do we need to load an internal repo from the client? (RHEL systems)


def check_perms():
    pass
    # todo: do we have rights to run yum as this user? Parse sudo -l to see if we have rights (or all:all)


def query_targets(program):
    """Probably deprecated now that we have a POC for paramiko"""
    print("Using dpkg to evaluate the installed version of " + QUERY_PROG)
    # Get the FQDN for the computer we're running on, send output to pipe
    # Use text=True here or you end up with type "bytes"
    hostname = subprocess.run(["hostname", "-f"], stdout=subprocess.PIPE, text=True)
    # Run a dpkg list, send output to pipe
    query_results = subprocess.Popen(["dpkg", "-l"], stdout=subprocess.PIPE, text=True)
    # Take stdout and run a grep for our program against it
    output = str(subprocess.check_output(["grep", program], stdin=query_results.stdout))
    query_results.wait()
    # Scrape the name and version from the results. Dpkg output should be consistent/sane
    output_firstline = output.split()[1:3]
    # Create a list, starting with the hostname
    query_results = [hostname.stdout.split()[0]]
    # Append program and version number to list. Return list to main
    for r in output_firstline:
        query_results.append(r)
    return query_results
    # todo: change this to run over ssh once that module is finished, unless it's completely different w/ AppDyn


def remediate_targets():
    pass
