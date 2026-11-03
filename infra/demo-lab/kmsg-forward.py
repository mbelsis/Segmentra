#!/usr/bin/env python3
"""Pass this machine's firewall log lines from the kernel to rsyslog.

Containers share one kernel. rsyslog's usual kernel input reads /proc/kmsg, which gives each line to
only ONE reader, so several machines would steal each other's lines at random. /dev/kmsg gives every
reader every line. It also holds the other machines' lines, so keep what a real machine would log for
itself: packets arriving for it, packets it sends and packets it routes. On a gateway (DEMO_GATEWAY=1)
routed means between its own networks. On a Swarm node (DEMO_SWARM_NODE=1) routed means traffic to its
published ports: every node has the same internal addresses, so the packet's destination MAC tells them apart.
"""
import ipaddress
import os
import re
import subprocess
import syslog

is_gateway = os.environ.get("DEMO_GATEWAY") == "1"
is_swarm_node = os.environ.get("DEMO_SWARM_NODE") == "1"
own_interfaces = [
    ipaddress.ip_interface(line.split()[3])
    for line in subprocess.run(["ip", "-o", "-4", "addr"], stdout=subprocess.PIPE, check=True).stdout.decode().splitlines()
    if line.split()[1] != "lo"
]
own_addresses = {str(i.ip) for i in own_interfaces}
own_networks = [i.network for i in own_interfaces]
own_mac = open("/sys/class/net/eth0/address").read().strip() if is_swarm_node else None


def on_own_network(address):
    try:
        return any(ipaddress.ip_address(address) in network for network in own_networks)
    except ValueError:  # IPv6: these labs filter IPv4 only
        return False


def is_mine(arriving, leaving, source, destination, message):
    if arriving and leaving:
        if is_swarm_node:
            return f"MAC={own_mac}" in message
        return is_gateway and on_own_network(source) and on_own_network(destination)
    return (arriving and destination in own_addresses) or (not arriving and source in own_addresses)


syslog.openlog("kernel", 0, syslog.LOG_KERN)

fd = os.open("/dev/kmsg", os.O_RDONLY)
os.lseek(fd, 0, os.SEEK_END)
while True:
    try:
        record = os.read(fd, 8192).decode("utf-8", "replace")
    except BrokenPipeError:  # the kernel overwrote lines before we read them; carry on with the next
        continue
    message = record.split(";", 1)[-1].strip()
    fields = re.search(r"\bIN=(\S*) OUT=(\S*) .*\bSRC=(\S+) DST=(\S+)", message)
    if fields and is_mine(*fields.groups(), message):
        syslog.syslog(syslog.LOG_WARNING, message)
