import re
import subprocess
import sys
import paramiko
from paramiko import SSHClient, AutoAddPolicy
import adcheck
from adcheck import QUERY_PROG
import find

machine_status = []


def create_session(target, key):
    """Establish a ssh connection with a target. Return the connection object"""
    print('----------------------')
    print('Trying ' + target)
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy)
    try:  # Connect to clients
        adcheck.logger.info(f'Trying to connect to {target}')
        if adcheck.args.user:  # If a user (-u) was passed, use that. Otherwise, use the current user
            adcheck.logger.info(f'Connecting as {adcheck.args.user}')
            client.connect(target, username=adcheck.args.user, key_filename=key)
            print("Connected to " + target)
        else:
            client.connect(target, key_filename=key)
    # Catch various errors and try to provide context when possible
    except paramiko.SSHException as e:
        # If we can't connect, put results in the list and log.
        adcheck.logger.error(f'Failed to connect to {target} --- {e}')
        machine_status.append([target, 'Connection failed'])
        print(e)
        print('There was an error connecting to the server (SSH KEY). Exiting')
        return
    except BlockingIOError as b:
        adcheck.logger.error(f'{target} is not reachable --- {b}')
        machine_status.append([target, 'Connection failed'])
        print(f'It looks like {target} is not reachable. Skipping')
        return
    except:
        adcheck.logger.error(f'{target} had some other type of error. Consider seeing if this user is valid --- ')
        machine_status.append([target, 'Connection failed'])
        print(f'It looks like {target} cannot be connected to. If the provided user valid? Skipping')
        return
    # If we connected successfully, proceed to evaluate the program version and report findings via console
    adcheck.logger.info(f'Connected to {target}')
    return client


def evaluate_version(tar, client):
    """Get information about app dynamics on a client. Put findings in a list"""
    # Check installed RPMs. Grep for the program we're looking for
    print('Evaluating version...')
    stdin, stdout, stderr = client.exec_command('rpm -qa | grep ' + adcheck.QUERY_PROG)
    if stdout.channel.recv_exit_status() == 0:
        rpm_output = stdout.read().decode("utf8")
        # If that output is not blank (we found it)
        if len(rpm_output) > 0:
            adcheck.logger.info(f'For {tar} found {rpm_output}')
            print('Found: ' + rpm_output)
            # Regex to get the version number from the package listing
            app_ver_re = re.search("appdynamics-machine-agent-(.*).x", rpm_output)
            app_version = app_ver_re.group(1)
            # Call a function to evaluate whether this version is vulnerable
            vuln_status = check_version_vulnerability(app_version)
            adcheck.logger.info(f'{tar} is {vuln_status}')
            # Add these results to the master results list.
            machine_status.append([tar, app_version, vuln_status])
            print(vuln_status)
        else:
            adcheck.logger.error(f'Client not found on {tar}')
            machine_status.append([tar, 'Client not found'])
            print('Client not found')
    # If grepping the package fails, note that happened and move on. Likely not installed.
    elif stdout.channel.recv_exit_status() == 1:
        adcheck.logger.error(f'Error code 1 received when searching for app dynamics on {tar}. Is it '
                             f'installed here? {stderr.read().decode("utf8")}')
        machine_status.append([tar, 'Failed to process app version. Is it installed?'])
        print(f'App Dynamics not found. Is it installed here? {stderr.read().decode("utf8")}')
    else:
        adcheck.logger.error(f'Nonspecific error encountered on {tar} {stderr.read().decode("utf8")}')
        machine_status.append([tar, 'Error'])
        print(f'ERROR: {stderr.read().decode("utf8")}')
    stdin.close()
    stdout.close()
    stderr.close()


def get_vulnerability_status_ssh(targets, key):
    """Connect to a list of remote machines via ssh. Parse out the version number of the App Dynamics machine client
    and determine whether it is vulnerable per the company's documentation. Provide output to console and logging.
    Return the completed list with vuln status."""
    # Iterate through the targets list and connect to them.
    # Nested loop because we end up with a list of lists for this function
    for t in targets:
        for tar in t:
            client = create_session(tar, key)
            if client:
                # Call find.py's functions
                log4j_vuln_status = find.check(client)
                evaluate_version(tar, client)

            # After all evaluation tasks are done, close out the connection. If we couldn't connect, and ended up with
            # a nonetype for client, we skip this and go to the next client.
            if client:
                client.close()
    return machine_status


def pass_test(connection):
    """This is a test function that accepts a ssh client and prints out pwd"""
    print('running pass test')
    stdin, stdout, stderr = connection.exec_command('pwd')
    print(stdout.read().decode("utf8"))
    stdin.close()
    stdout.close()
    stderr.close()


def check_version_vulnerability(ver):
    """Function that breaks down version numbers, which are separated by periods. Evaluates to three places"""
    check_ver = re.search("(\d*).(\d*).(\d*).(\d*)", ver)
    nonvuln_split = adcheck.NON_VULNERABLE_VERSION.split('.')
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


def remediate_targets(targets, key):
    # WIP
    """Connect back to clients that are running a vulnerable version of app dynamics and update them"""
    # Clear the machine status list since the first run is already parsed out into more specific status lists
    machine_status.clear()
    for t in targets:
        for tar in t:
            client = create_session(tar, key)
            if client:
                # Probably not using stdout for the update, but we're taking it anyway for logs
                # Update appdynamics, restart service
                stdin, stdout, stderr = client.exec_command('sudo yum -y ' + adcheck.QUERY_PROG)
                adcheck.logger.info(f'Yum install status: {stdout,stderr}')
                stdin, stdout, stderr = client.exec_command('sudo systemctl restart ' + adcheck.QUERY_PROG)
                adcheck.logger.info(f'Restarting appdynamics: {stdout, stderr}')
                # Check version again. If this still gives us a vuln version, manual steps are needed by user.
                evaluate_version(tar, client)
            else:
                adcheck.logger.error(f'Could not connect to {tar}. Skipping update')
            # After all evaluation tasks are done, close out the connection. If we couldn't connect, and ended up with
            # a nonetype for client, we skip this and go to the next client. This shouldn't happen at this phase.
            if client:
                client.close()
    return machine_status
