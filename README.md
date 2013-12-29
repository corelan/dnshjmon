dnshjmon
========

dnshjmon is a free tool to monitor public DNS records and report hijacks


Usage
=====
python dnshjmon.py [arguments]

Simply create a flat file (dnshjmon_dns.conf) that contains

hostname=ip,ip,ip,ip

(one line per hostname)

Run the script one time, and use the wizard to specify smtp details,
and then schedule the script.
