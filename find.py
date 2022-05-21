#! /usr/bin/python3
#jschump
import subprocess, re, csv


#1) come up with a way to find if the machine is running appdynamis, check services then location. If neither show up end script
def check():
    lscheck1 = subprocess.run(['ls', '/opt/appdynamics/machine-agent/'])
    if lscheck1.returncode == 0:
        find_core = subprocess.run(['find', '/opt/', '-name', 'log4j-core*'], stdout=subprocess.PIPE).stdout.splitlines()
#print(find_core)
        find_api = subprocess.run(['find', '/opt/', '-name', 'log4j-*'], stdout=subprocess.PIPE).stdout.splitlines()
        for x in find_core:
            x = str(x)
            check_ver = re.search("-[0-9]+.(\d*).(\d*)", x)
            check = str(check_ver.group(0))
            output = (check[1:])
            #print(output)
            output = '2.14.1'
            verify(output)
    else:
        print('no appdynamics found')
        exit
#2) take the output of the log4js file and parse it so it you can the csv
#3) check the log4js to the csv file - this portion needs to check both sides and to use wild cards - such as 2.17.* is at risk if it was 2.17 but not 2.17.1
def verify(output):
    with open('/home/jschump/test.csv', 'r') as testfile:
        read = csv.reader(testfile, delimiter=',')
    # reading csv
        for row in read:
    # checking if v_level is high
            if row[4] == 'high':
                test = row[1].split(",")
    # spliting all versions
                for v_risk in test:
                    if v_risk == output: # passed in version from other funciton
                        print('at  high risk')

    # if statement to check if grabed data from computer matches at rick
            elif row[4] == 'medium':
                test = row[1].split(",")
    # spliting all versions
                for v_risk in test:
                    if v_risk == output:  # passed in version from other funciton
                        print('at medium risk')
        #else:
 #test = row[1].split(",")
            # spliting all versions
        #    for v_risk in test:
        #        if v_risk == '9':  # passed in version from other funciton
        #            print('at risk')
        #        else:
        #            print("no issues found")
check()

#4) if there is a error found you have to notify the user running the script and to append to a csv the name of the server and the log4j error they have/what version they need to upgrade to


#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# THINGS TO WORK ON
# 1) clean up tabbing/spacing - this was caused by vim
# 2) make more modular - both the grabbing of the log4j files and the checking aginst the list
# 3) step 4 needs to be completed
# 4) parts of the script needs to be changed to be run aginst another computer
# you can call me at 206-794-2562 or message me on discord




#import subprocess

#ls = "ls"

#lscheck = subprocess.Popen([ls, '/opt/appdynamics/machine-agent/'], capture_output=True)


#lscheck = subprocess.run([ls, '/opt/appdynamics/machine-agent/'])

#print(lscheck)
#if lscheck.returncode == 0:
#    print('yes')
#else:
#    print('bad')

#find = "find"

#finder = subprocess.Popen([find, '

#VSC Test Change 

#1) come up with a way to find if the machine is running appdynamis, check services then location. If neither show up end script

#2) take the output of the log4js file and parse it so it you can the csv

#3) check the log4js to the csv file - this portion needs to check both sides and to use wild cards - such as 2.17.* is at risk if it was 2.17 but not 2.17.1

#4) if there is a error found you have to notify the user running the script and to append to a csv the name of the server and the log4j error they have/what version they need to upgrade to                                                                                                                                                                                               
