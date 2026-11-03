#!/usr/bin/env python3
"""Pass this machine's firewall log lines from the kernel to rsyslog.

Containers share one kernel. rsyslog's usual kernel input reads /proc/kmsg, which gives each line to
only ONE reader, so several machines would steal each other's lines at random. /dev/kmsg gives every
reader every line. It also holds the other machines' lines, so keep what a real machine would log for
itself: packets arriving for it, and packets it sends.
"""
import os
import re
import socket
import syslog

self_ip = socket.gethostbyname(socket.gethostname())
syslog.openlog("kernel", 0, syslog.LOG_KERN)

fd = os.open("/dev/kmsg", os.O_RDONLY)
os.lseek(fd, 0, os.SEEK_END)
while True:
    try:
        record = os.read(fd, 8192).decode("utf-8", "replace")
    except BrokenPipeError:  # the kernel overwrote lines before we read them; carry on with the next
        continue
    message = record.split(";", 1)[-1].strip()
    fields = re.search(r"\bIN=(\S*) .*\bSRC=(\S+) DST=(\S+)", message)
    if not fields:
        continue
    arriving, source, destination = fields.groups()
    if (arriving and destination == self_ip) or (not arriving and source == self_ip):
        syslog.syslog(syslog.LOG_WARNING, message)
