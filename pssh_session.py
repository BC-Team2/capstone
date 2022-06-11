#!/usr/bin/env python3
"""Library for connecting to clients using paramiko and evaluating app dynamics for log4j vulnerabilities"""
# Lead architect and developer - Josh Parmely https://www.linkedin.com/in/jparmely/
import re
import paramiko
from paramiko import SSHClient, AutoAddPolicy
import adcheck
import find

machine_status = []


def create_session(target, key, params):
    """Establish an ssh connection with a target. Return the connection object"""
    print('----------------------')
    print('Trying ' + target)
    # For debug - will show the params passed to client.connect after 'target'.
    # WARNING: Will show password in plaintext.
    # Create a new SSHClient object
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy)
    try:  # Connect to clients using the current target, and a dict containing arguments for the SSH session
        adcheck.logger.info(f'Trying to connect to {target}')
        client.connect(target, **params)
    # Catch various errors and try to provide context when possible
    except paramiko.SSHException as e:
        # If we can't connect, put results in the list and log.
        adcheck.logger.error(f'Failed to connect to {target} --- {e}')
        machine_status.append([target, 'Connection failed', 'Unknown'])
        print(e)
        print('There was an error connecting to the server (SSH KEY). Exiting')
        return
    except BlockingIOError as b:
        adcheck.logger.error(f'{target} is not reachable --- {b}')
        machine_status.append([target, 'Connection failed', 'Unknown'])
        print(f'It looks like {target} is not reachable. Skipping')
        return
    except:
        adcheck.logger.error(f'{target} had some other type of error. Consider seeing if this user is valid --- ')
        machine_status.append([target, 'Connection Failed', 'Unknown'])
        print(f'It looks like {target} cannot be connected to. Is the provided user valid? Skipping')
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
            # Call find.py's functions to check log4j version used by appdyn to verify findings
            log4j_vuln_status = find.check_log4jcore(client)
            # Regex to get the version number from the package listing
            app_ver_re = re.search("appdynamics-machine-agent-(.*).x", rpm_output)
            app_version = app_ver_re.group(1)
            # Call a function to evaluate whether this version is vulnerable
            vuln_status = check_version_vulnerability(app_version)
            adcheck.logger.info(f'Vulnerability result: {vuln_status} for {tar}')
            # Add these results to the master results list.
            machine_status.append([tar, app_version, vuln_status, log4j_vuln_status])
            print(vuln_status)
        else:
            adcheck.logger.error(f'Client not found on {tar}')
            machine_status.append([tar, 'Client not found'])
            print('Client not found')
    # If grepping the package fails, note that happened and move on. Likely not installed.
    elif stdout.channel.recv_exit_status() == 1:
        adcheck.logger.warning(f'Error code 1 received when searching for app dynamics on {tar}. Is it '
                               f'installed here? {stderr.read().decode("utf8")}')
        machine_status.append([tar, 'Failed to process app version. Is it installed?', 'Unknown'])
        print(f'App Dynamics not found. Is it installed here? {stderr.read().decode("utf8")}')
    else:
        adcheck.logger.error(f'Nonspecific error encountered on {tar} {stderr.read().decode("utf8")}')
        machine_status.append([tar, 'Error'])
        print(f'ERROR: {stderr.read().decode("utf8")}')
    stdin.close()
    stdout.close()
    stderr.close()


def get_vulnerability_status_ssh(targets, key, params):
    """Connect to a list of remote machines via ssh. Parse out the version number of the App Dynamics machine client
    and determine whether it is vulnerable per the company's documentation. Provide output to console and logging.
    Return the completed list with vuln status."""
    # Iterate through the targets list and connect to them.
    # Nested loop because we end up with a list of lists for this function
    for t in targets:
        for tar in t:
            client = create_session(tar, key, params)
            if client:
                evaluate_version(tar, client)

            # After all evaluation tasks are done, close out the connection. If we couldn't connect, and ended up with
            # a nonetype for client, we skip this and go to the next client.
            if client:
                client.close()
                adcheck.logger.info(f'Connection closed to {tar}')
    return machine_status


def pass_test(connection):
    """This is a test function that accepts an ssh client and prints the pwd command"""
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


def remediate_targets(targets, key, params):
    """Connect back to clients that are running a vulnerable version of app dynamics and update them"""
    # Clear the machine status list since the first run is already parsed out into more specific status lists
    machine_status.clear()
    for tar in targets:
        client = create_session(tar, key, params)
        if client:
            # Update appdynamics, restart service
            print('Starting appdynamics update process - Updating through yum ')
            adcheck.logger.info(f'Starting appdynamics update process for {tar}')
            stdin, stdout, stderr = client.exec_command('sudo yum install -y ' + adcheck.QUERY_PROG)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                print('Update completed')
                adcheck.logger.info(f'Yum install status: {stdout.read().decode("utf8"), stderr.read().decode("utf8")}')
            else:
                print(f'Error installing appdynamics. Please check log: {exit_status} {stderr.read().decode("utf8")}')
                adcheck.logger.error(f'Yum update status: {stdout.read().decode("utf8"), stderr.read().decode("utf8")}')
            print('Restarting appdynamics service')
            adcheck.logger.info(f'Restarting appdynamics service on {tar}')
            stdin, stdout, stderr = client.exec_command('sudo systemctl restart ' + adcheck.QUERY_PROG)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                print('Service restarted')
                adcheck.logger.info(f'Service restarted on {tar}')
            else:
                print(f'Error restarting service, {exit_status} {stderr.read().decode("utf8")}')
                adcheck.logger.error(f'Error restarting appdynamics service on {tar} {stderr.read().decode("utf8")}')
            # Check version again. If this still gives us a vuln version, manual steps are needed by user.
            # This is essentially any clients that failed to update
            evaluate_version(tar, client)
        else:
            adcheck.logger.error(f'Could not connect to {tar}. Skipping update')
        # After all evaluation tasks are done, close out the connection. If we couldn't connect, and ended up with
        # a nonetype for client, we skip this and go to the next client. This shouldn't happen at this phase.
        if client:
            client.close()
    return machine_status
