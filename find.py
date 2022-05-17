#! /usr/bin/python3

import subprocess

ls = "ls"

#lscheck = subprocess.Popen([ls, '/opt/appdynamics/machine-agent/'], capture_output=True)


lscheck = subprocess.run([ls, '/opt/appdynamics/machine-agent/'])

print(lscheck)
if lscheck.returncode == 0:
    print('yes')
else:
    print('bad')

#find = "find"

#finder = subprocess.Popen([find, '



#1) come up with a way to find if the machine is running appdynamis, check services then location. If neither show up end script

#2) take the output of the log4js file and parse it so it you can the csv

#3) check the log4js to the csv file - this portion needs to check both sides and to use wild cards - such as 2.17.* is at risk if it was 2.17 but not 2.17.1

#4) if there is a error found you have to notify the user running the script and to append to a csv the name of the server and the log4j error they have/what version they need to upgrade to
~                                                                                                                                                                                                  
