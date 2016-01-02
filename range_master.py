#!/usr/bin/env python

import sys
with open(sys.argv[1]) as cr:
 cra = list(cr.readlines())
for crar in cra:
 (ads, cs) = str(crar).split('/')
 addr = ads.split('.')
 addr[3] = 1
 cidr = int(str(cs).strip())
 mask = [0, 0, 0, 0]
 for i in range(cidr):
        mask[i/8] = mask[i/8] + (1 << (7 - i % 8))
 net = []
 for i in range(4):
        net.append(int(addr[i]) & mask[i])
 broad = list(net)
 brange = 32 - cidr
 for i in range(brange):
        broad[3 - i/8] = broad[3 - i/8] + (1 << (i % 8))
 broad[3] = broad[3]-1
 print str(crar).strip() +", " + ".".join(map(str, addr)) + " - " + ".".join(map(str, broad))
