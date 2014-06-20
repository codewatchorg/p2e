p2e
===

Process to escalate to, or p2e, identifies processes on remote hosts running under potentially privileged accounts to be used for escalation in penetration tests

Requirements
============

Impacket
pywin32

Usage
=====

p2e.py [-h] --iplist IPLIST --user USER --pass PASS [--domain DOMAIN]
              --type TYPE

  Find running process that can be used to escalate access.

  optional arguments:
  
    -h, --help       show this help message and exit
    --iplist IPLIST  file list of IPs that we can login with using provided
                     username and password (default: None)
    --user USER      the username to use for authentication (default: None)
    --pass PASS      the password to use for authentication (default: None)
    --domain DOMAIN  the Domain to use for authentication (default: )
    --type TYPE      which type of connection to we use, WMI or SMB (default:
                     None)

  Example: p2e.py --iplist iplist.txt --user test --pass testpass --domain 
             testdomain --type smb
