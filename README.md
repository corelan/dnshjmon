dnshjmon
========

dnshjmon is a free tool to monitor public DNS records and report hijacks


Syntax
------
python dnshjmon.py [arguments]

Valid arguments:


    -h                  : show help
    -d <dns configfile> : full path to dns config file.
                          Defaults to dnshjmon_dns.conf in current folder
    -s <smtp configfile : full path to smtp config file.
                          Defaults to dnshjmon_smtp.conf in current folder
    -mail               : Test e-mail configuration


DNS Config file
----------------
This is a flat ascii file (dnshjmon_dns.conf) that contains the list with hostnames that need to be checked and the list with valid IPs for that hostname.

`hostname=ip`

You can specify multiple IP addresses and/or even use CIDR notation. Simply separate entries with a comma:

`hostname=127.0.0.1,192.168.0.1/25`

If you want to exclude a certain IP, prefix it with a dash  

`hostname=127.0.0.1,192.168.0.1/25,-192.168.0.5`


SMTP Config file
----------------
This file (dnshjmon_smtp.conf) will be created the first time you run dnshjmon.py, using an interactive wizard.
If you want to add additional mailserver configurations or change the existing one, simply edit the conf file.
You can test if the mail configuration works correctly by using the `-mail` argument.
By default, emails will be sent with high-priority and requesting a return-receipt.

Usage
-----

Simply schedule the script as a Cron job or Scheduled Task.
Please note that the script was written and tested against python 2.7.
More info: https://www.corelan.be/index.php/2013/12/29/a-chain-is-only-as-strong-as-its-weakest-link-dns-hijack-monitoring/

Disclaimer
----------
Use at your own risk.
