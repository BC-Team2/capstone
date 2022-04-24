import subprocess

from main import QUERY_PROG


def connect_to_targets():
    pass
    # This probably is where a list or a single target is passed to pssh with a command/set of commands to
    # run. Could be used to query version or to apply remediation.
    # Need to decide whether key authentication or pass authentication is going to be used
    # todo: check whether or not we can successfully connect to machines https://stackoverflow.com/questions/1405324/how-to-create-a-bash-script-to-check-the-ssh-connection
    # todo: create connections to remote machines to that commands can be passed to the session


def install_repo():
    pass  # Do we need to load an internal repo from the client? (RHEL systems)


def check_perms():
    pass
    # todo: do we have rights to run yum as this user? Parse sudo -l to see if we have rights (or all:all)


def query_targets(program):
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
