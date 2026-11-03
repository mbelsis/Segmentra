#!/bin/sh
# A stand-in SIEM for scripts/demo-lab.py and the integration test: receives syslog on port 514 and
# writes each message exactly as it arrived, one file per protocol.
set -eu

mkdir -p /var/log/siem
touch /var/log/siem/udp.log /var/log/siem/tcp.log

cat > /etc/rsyslog-siem.conf <<'RSYSLOG'
global(maxMessageSize="64k")
module(load="imudp")
module(load="imtcp")
template(name="asReceived" type="string" string="%rawmsg%\n")
ruleset(name="fromUdp") { action(type="omfile" file="/var/log/siem/udp.log" template="asReceived") }
ruleset(name="fromTcp") { action(type="omfile" file="/var/log/siem/tcp.log" template="asReceived") }
input(type="imudp" port="514" ruleset="fromUdp")
input(type="imtcp" port="514" ruleset="fromTcp")
RSYSLOG

rm -f /run/rsyslogd.pid
exec rsyslogd -n -f /etc/rsyslog-siem.conf
