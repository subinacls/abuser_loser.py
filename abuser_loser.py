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
# make fail2banlist
#with open(tlr) as f:
# fr = f.readlines()
#for x in fr:
try:
 if a['MD5'] == f2bl:
  print "\t[INFO] Nothing has changed in the fail2ban.log\n\t\t[INFO] Quitting ..."
except Exception as fail2log:
 a['MD5'] = f2bl

if a['MD5'] != f2bl:
 print "\t[INFO] fail2ban.log has changed in the fail2ban.log\n\t\t[INFO] Starting processing ..."

for x in tlr:
 #print x
 # parse sections IP and Date
 xr = str(x).split()[0]
 xd = " ".join(str(x).split()[1::])
 #print xd
 #print xr
 # split and strip ip address
 t = str(xr).split(".")[0]
 u = str(xr).split(".")[1]
 v = str(xr).split(".")[2]
 w = str(xr).split(".")[3].strip()
 #print t
 #print u
 #print v
 #print w
 #check Keys in JSON
 if t not in a.keys():
  a[t] = {}
  a[t]["tcount"] = 1
 else:
  a[t]["tcount"] = a[t]["tcount"] + 1
 if u not in a[t].keys():
  a[t][u] = {}
  a[t][u]["ucount"] = 1
 else:
  a[t][u]["ucount"] = a[t][u]["ucount"] + 1
 if v not in a[t][u].keys():
  a[t][u][v] = {}
  a[t][u][v]["vcount"] = 1
 else:
  a[t][u][v]["vcount"] = a[t][u][v]["vcount"] + 1
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
   print "\t[INFO] Abuser Identified: " + str(xr)
   a[t][u][v][w]['rules']["permaban"] =  a[t][u][v][w]['rules']["permaban"] + 1
  if a[t][u][v][w]['rules']["permaban"] == 1:
   print "\t\t[WARNING] Permaban Action taken in iptables"
   ipset.append(xr)
#print a
# dump JSON file
with open(jlogfile, 'w') as outfile:
 json.dump(a, outfile, sort_keys = True, indent = 4,ensure_ascii=False)
#print a
# write ipset list
with open("ipset_list","a") as ipsetlist:
 for ipsetw in ipset:
  ipsetlist.write(str(ipsetw)+"\n")
