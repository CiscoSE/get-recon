# get-recon
experiments with multiprocess, socket and subprocess

This simple script ping sweeps a network with nmap and then uses nmap to fingerprint each of the active hosts.  I leverage subprocess to launch nmap.  The script leverages multiprocess to parallelize the fingerprint scans.  Finally, I use socket to enable better sorting of IP addresses.

#Change Log

5/6/19 added rotating logs for debugging