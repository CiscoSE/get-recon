''' a quick project to take the output from an nmap scan and run it 
through a series of checks.  configure integration with openvas.
'''

import subprocess
import logging.handlers
import json
import multiprocessing
import socket
# import sys
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
            logger.debug('hostlist [host down] ' + line)
        elif 'Nmap scan report for' in line:
            hosts.append(line[21:])
        else:
            logger.debug('hostlist junk line ' + line)
    outfile=open('live-hosts.txt', 'w+')
    for line in hosts:
        outfile.write(line + '\n')
    outfile.close()
    return hosts
def hostscanfunc(line):
    logger.info('hostscanfunc ' + line)
    nmap = subprocess.Popen(['nmap', '-A', '-T4', line], stdout=subprocess.PIPE)
    output = list(nmap.communicate()[0].decode("utf-8").split('\n'))
    hostscan[line] = output
    # return hostscan
if __name__ == '__main__':
    logger = logging.getLogger('get-recon')
    logger.setLevel(logging.DEBUG)
    logfile = logging.handlers.RotatingFileHandler('get-recon.log', maxBytes=100000, backupCount=3)
    logfile.setLevel(logging.DEBUG)
    console = logging.StreamHandler()
    console.setLevel(logging.WARN)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logfile.setFormatter(formatter)
    console.setFormatter(formatter)
    logger.addHandler(logfile)
    logger.addHandler(console)
    output = nmap()
    hosts = hostlist(output)
    logger.debug('main ' + str(hosts))
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
