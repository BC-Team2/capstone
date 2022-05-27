import re
import subprocess
import sys
import paramiko
from paramiko import SSHClient, AutoAddPolicy
import adcheck
from adcheck import QUERY_PROG


def get_vulnerability_status_ssh(targets, key):
    """Connect to a list of remote machines via ssh. Parse out the version number of the App Dynamics machine client
    and determine whether it is vulnerable per the company's documentation. Provide output to console and logging."""
    machine_status = []
    client = SSHClient()
    # client.load_host_keys(filename=ssh_key)
    client.set_missing_host_key_policy(AutoAddPolicy)
    # client.load_system_host_keys()
    # Iterate through the targets list and connect to them.
    # Nested loop because we end up with a list of lists for this function
    for t in targets:
        for tar in t:
            print('----------------------')
            print('Trying ' + tar)
            try:  # Connect to clients
                adcheck.logger.info(f'Trying to connect to {tar}')
                client.connect(tar, username='jparmrat', key_filename=key)
                # TODO: Either remove the username param altogether and assume user names match, or add a switch.
            except paramiko.SSHException as e:
                # If we can't connect, put results in the list and log.
                adcheck.logger.error(f'Failed to connect to {tar} --- {e}')
                machine_status.append([tar, 'Connection failed'])
                print(e)
                print('There was an error connecting to the server (SSH KEY). Exiting')
                continue  # If the connection process blows up, log, append results and move on
            except BlockingIOError as b:
                adcheck.logger.error(f'{tar} is not reachable --- {b}')
                machine_status.append([tar, 'Connection failed'])
                print(f'It looks like {tar} is not reachable. Skipping')
                continue  # If the connection process blows up, log, append results and move on

            # If we connected successfully, proceed to evaluate the program version and report findings via console
            adcheck.logger.info(f'Connected to {tar}')
            print("Connected to " + tar + ", running checks")
            # Check installed RPMs. Grep for the program we're looking for
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
                    vuln_status = eval_version(app_version)
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
            # Close out all of these files to clean up
            stdin.close()
            stdout.close()
            stderr.close()
            client.close()


def eval_version(ver):
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
    # Append program and version number to list. Return list to adcheck
    for r in output_firstline:
        query_results.append(r)
    return query_results
    # todo: change this to run over ssh once that module is finished, unless it's completely different w/ AppDyn


def remediate_targets():
    pass
