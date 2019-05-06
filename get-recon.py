''' a quick project to take the output from an nmap scan and run it 
through a series of checks.  configure integration with openvas.
Maybe add logging? '''

import subprocess
# import sys
import json
import multiprocessing
import socket

hosts = []
junk = 0
hostscan = {}

def nmap():
    # nmap = subprocess.Popen(['nmap', '-v', '-sn', '192.168.0.0/16', '10.0.0.0/8'], stdout=subprocess.PIPE)
    nmap = subprocess.Popen(['nmap', '-v', '-sn', '192.168.128.0/24'], stdout=subprocess.PIPE)
    # nmap = subprocess.Popen(['nmap', '-v', '-sn', sys.argv[1]], stdout=subprocess.PIPE)
    output = list(nmap.communicate()[0].decode("utf-8").split('\n'))
    return output
def hostlist(output):
    for line in output:
        if '[host down]' in line:
            junk = 0
        elif 'Nmap scan report for' in line:
            hosts.append(line[21:])
        else:
            junk = 0
    outfile=open('live-hosts.txt', 'w+')
    for line in hosts:
        outfile.write(line + '\n')
    outfile.close()
    return hosts
def hostscanfunc(line):
    print(line)
    nmap = subprocess.Popen(['nmap', '-A', '-T4', line], stdout=subprocess.PIPE)
    output = list(nmap.communicate()[0].decode("utf-8").split('\n'))
    hostscan[line] = output
    # return hostscan
if __name__ == '__main__':
    output = nmap()
    hosts = hostlist(output)
    print(hosts)
    pool_size = 4
    manager = multiprocessing.Manager()
    hostscan = manager.dict()
    hostscanprocess = multiprocessing.Pool(pool_size)
    results = hostscanprocess.map_async(hostscanfunc, hosts)
    hostscanprocess.close()
    hostscanprocess.join()
    outfile=open('hostscan.txt', 'a+')
    outfile.write(json.dumps(sorted(hostscan.items(), key=lambda item: socket.inet_aton(item[0])), indent=4))
    outfile.close()
