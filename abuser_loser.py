#/usr/bin/env python
import hashlib
import json
import time
import sys
import os

# check hash value of fail2ban log
def md5(fname):
    hash = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()
f2bl = md5('/var/log/fail2ban.log')

#read log
jlogfile = "Jbusefile"
try:
 with open(jlogfile) as jlf:
  a = json.load(jlf)
except Exception as e:
 a = {}
 pass

# ipset list
ipset = []
# read system log from fail2ban
tl = os.popen('cat /var/log/fail2ban.log* | grep -viE "Unban|INFO" | sed -r "s/(((.*)(.*)),(.*) Ban (.*))/\\6 \\3/g"')# > fail2banlist')
tl
tlr = tl.readlines()
# check MD5 sums to process file or not
try:
 if a['MD5'] == f2bl:
  print "\t[INFO] Nothing has changed in the fail2ban.log"
  print "\t[INFO] Logged MD5sum of: '/var/log/fail2ban.log' - " + str(f2bl)
  print "\t[INFO] System MD5sum of: '/var/log/fail2ban.log' - " + str(os.popen('md5sum /var/log/fail2ban.log').read()).split()[0]
  print "\t\t[INFO] Quitting ..."
  sys.exit(0)
except Exception as fail2log:
 pass

if a['MD5'] != f2bl:
 print "\t[INFO] fail2ban.log has changed in the fail2ban.log\n\t\t[INFO] Starting processing ..."
 a['MD5'] = f2bl

# process file
for x in tlr:
 # parse sections IP and Date
 xr = str(x).split()[0]
 xd = " ".join(str(x).split()[1::])
 # split and strip ip address
 t = str(xr).split(".")[0]
 u = str(xr).split(".")[1]
 v = str(xr).split(".")[2]
 w = str(xr).split(".")[3].strip()
 #check Keys in JSON
 if t not in a.keys():
  a[t] = {}
  a[t]["tcount"] = 1
  a[t]['rules'] = {}
  a[t]['log'] = {}
  a[t]['rules']['abuser'] = 0
  a[t]['rules']['permaban'] = 0
  a[t]['log']['firstseen'] = xd
  a[t]['log']['lastseen'] = xd
  a[t]['log']['everytime'] = []
  a[t]['log']['everytime'].append(xd)
 else:
  a[t]["tcount"] = a[t]["tcount"] + 1
  a[t]['log']['lastseen'] = xd
  if xd in a[t]['log']['everytime']:
   break
  else:
   a[t]['log']['everytime'].append(xd)
 if a[t]['rules']["permaban"] == 1:
  pass
 else:
  if a[t]["tcount"] != 60:
   a[t]['rules']["abuser"] = a[t]['rules']["abuser"] + 1
  if a[t]['rules']["abuser"] == 30:
   print "\t[INFO] T-Rule Abuser Identified: " + str(xr)
   a[t]['rules']["permaban"] =  a[t]['rules']["permaban"] + 1
  if a[t]['rules']["permaban"] == 20:
   print "\t\t[WARNING] T-Rule Permaban Action taken in iptables"
   ipset.append(xr)

 if u not in a[t].keys():
  a[t][u] = {}
  a[t][u]["ucount"] = 1
  a[t][u]['rules'] = {}
  a[t][u]['rules']['abuser'] = 0
  a[t][u]['rules']['permaban'] = 0
  a[t][u]['log'] = {}
  a[t][u]['log']['firstseen'] = xd
  a[t][u]['log']['lastseen'] = xd
  a[t][u]['log']['everytime'] = []
  a[t][u]['log']['everytime'].append(xd)
 else:
  a[t][u]["ucount"] = a[t][u]["ucount"] + 1
  a[t][u]['log']['lastseen'] = xd
  if xd in a[t][u]['log']['everytime']:
   break
  else:
   a[t][u]['log']['everytime'].append(xd)
 if a[t][u]['rules']["permaban"] == 1:
  pass
 else:
  if a[t][u]["ucount"] != 40:
   a[t][u]['rules']["abuser"] = a[t][u]['rules']["abuser"] + 1
  if a[t][u]['rules']["abuser"] == 20:
   print "\t[INFO] U-Rule Abuser Identified: " + str(xr)
   a[t][u]['rules']["permaban"] =  a[t][u]['rules']["permaban"] + 1
  if a[t][u]['rules']["permaban"] == 20:
   print "\t\t[WARNING] U-Rule Permaban Action taken in iptables"
   ipset.append(xr)

 if v not in a[t][u].keys():
  a[t][u][v] = {}
  a[t][u][v]["vcount"] = 1
  a[t][u][v]['rules'] = {}
  a[t][u][v]['rules']['abuser'] = 0
  a[t][u][v]['rules']['permaban'] = 0
  a[t][u][v]['log'] = {}
  a[t][u][v]['log']['firstseen'] = xd
  a[t][u][v]['log']['lastseen'] = xd
  a[t][u][v]['log']['everytime'] = []
  a[t][u][v]['log']['everytime'].append(xd)
 else:
  a[t][u][v]["vcount"] = a[t][u][v]["vcount"] + 1
  a[t][u][v]['log']['lastseen'] = xd
  if xd in a[t][u][v]['log']['everytime']:
   break
  else:
   a[t][u][v]['log']['everytime'].append(xd)
 if a[t][u][v]['rules']["permaban"] == 1:
  pass
 else:
  if a[t][u][v]["vcount"] != 30:
   a[t][u][v]['rules']["abuser"] = a[t][u][v]['rules']["abuser"] + 1
  if a[t][u][v]['rules']["abuser"] == 15:
   print "\t[INFO] V-Rule Abuser Identified: " + str(xr)
   a[t][u][v]['rules']["permaban"] =  a[t][u][v]['rules']["permaban"] + 1
  if a[t][u][v]['rules']["permaban"] == 10:
   print "\t\t[WARNING] V-Rule Permaban Action taken in iptables"
   ipset.append(xr)

 if w not in a[t][u][v].keys():
  a[t][u][v][w] = {}
  a[t][u][v][w]["wcount"] = 1
  a[t][u][v][w]['rules'] = {}
  a[t][u][v][w]['rules']['abuser'] = 0
  a[t][u][v][w]['rules']['permaban'] = 0
  a[t][u][v][w]['log'] = {}
  a[t][u][v][w]['log']['firstseen'] = xd
  a[t][u][v][w]['log']['lastseen'] = xd
  a[t][u][v][w]['log']['everytime'] = []
  a[t][u][v][w]['log']['everytime'].append(xd)
 else:
  a[t][u][v][w]["wcount"] = a[t][u][v][w]["wcount"] + 1
  a[t][u][v][w]['log']['lastseen'] = xd
  if xd in a[t][u][v][w]['log']['everytime']:
   break
  else:
   a[t][u][v][w]['log']['everytime'].append(xd)
 if a[t][u][v][w]['rules']["permaban"] == 1:
  pass
 else:
  if a[t][u][v][w]["wcount"] != 6:
   a[t][u][v][w]['rules']["abuser"] = a[t][u][v][w]['rules']["abuser"] + 1
  if a[t][u][v][w]['rules']["abuser"] == 3:
   print "\t[INFO] W-Rule Abuser Identified: " + str(xr)
   a[t][u][v][w]['rules']["permaban"] =  a[t][u][v][w]['rules']["permaban"] + 1
  if a[t][u][v][w]['rules']["permaban"] == 1:
   print "\t\t[WARNING] W-Rule Permaban Action taken in iptables"
   ipset.append(xr)

# dump JSON file
with open(jlogfile, 'w') as outfile:
 json.dump(a, outfile, sort_keys = True, indent = 4,ensure_ascii=False)

# write ipset list
with open("ipset_list","a") as ipsetlist:
 for ipsetw in ipset:
  ipsetlist.write(str(ipsetw)+"\n")
