# App Dynamics log4j Remediation Script
This script is used to evaluate the version of App Dynamics machine agents, and if they are a version that is vulnerable to one of the log4j CVEs, update it from your local RPM repository (yum install).

## Requirements
+ Python3
+ paramiko libraries (pip install paramiko)
+ A user account on remote systems that has the ability to run yum install through sudo with no credential prompt
+ An RPM repository that contains the current version of appdynamics-machine-agent

## Functionality overview
This program makes remote connections over SSH to the list of remote devices supplied to it, and then acquires the version number of the appdynamics-machine-agent package. This version number is then evaluated to see whether or not it is greater than or equal to the version number that is reported by the vendor to no longer be vulnerable to the various log4j exploits. 

If app dynamics is determined to be vulnerable, the program updates the package using yum, which will install the current package hosted on in the environment's package repository. A report will be generated with the versions/dispositions of the machines evaluated.

## Usage
`python3 adcheck.py -t TARGETS_FILE [optional parameters]`
### Parameters
-h Print help

-t The location of the list of addresses to evaluate

-i The path to your SSH private key

-u The user to authenticate as, if different than the currently logged in user

-p Set this flag to be prompted for a password, to be used as the passphrase for your SSH key, or for login

-c Set this flag to run in CHECK ONLY mode, which will not make changes to the target systems

Output of application versions/statuses will be found in a time-stamped csv contained in the "output" folder.

A log file containing details of the process is found in "log.log"

### Example usage
Use targets.csv as your targets list, using ~/.ssh/install_account as your SSH key, and timmy as your user account.

`python3 adcheck.py -t targets.csv -i ~/.ssh/install_account -u timmy`

Use targets.csv as your targets list, timmy as your user account, and ask for a password (for the timmy user account).

`python3 adcheck.py -t targets.csv -u timmy -p`

Use targets.csv as your targets list, steve as your user account, ~/.ssh/secret_key as your SSH key, and ask for a password (for the key passphrase).

`python3 adcheck.py -t targets.csv -u steve -i ~/.ssh/secret_key -p`

## Modifiable variables 
Some variables within adcheck.py can be changed to suit your environment. They can be found under the imports, and above the first function.

+ NON\_VULNERABLE_VERSION - The version number that is no longer vulnerable. Default is 21.11.2
+ QUERY_PROG - The name of the package to evaluate. Default is "appdynamics-machine-agent"
+ SSH_PORT - The port used to make a SSH connection. Default is 22
+ logger.setLevel(logging.INFO) - The level of logging to capture. Default is INFO (all events of INFO or more severe), but it can be changed to DEBUG to make paramiko more verbose

Additionally, APP\_DYN_PATH can be modified within find.py to change the path to your machine agent path. The default is "/opt/appdynamics"
