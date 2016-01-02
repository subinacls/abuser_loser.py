# abuser_loser.py
supplimental logic to identify abusers over time with fail2ban for ipset permaban 


monitors fail2ban.log for persistent bans across time
logs to JSON file
monitors by octet

1.2.3.4 would break out to 
    1.0.0.0/8
    1.2.0.0/16
    1.2.3.0/24
    1.2.3.4/32
  
This keeps track of persistent offenders by subnet and ranges which is compaired to a list of known ranges.
This will eventually take into concideration the different subnets and their location and based on a score
Entire subnets of countries could potentially be bannd but it will have to work its way through the scoring system
based from a single ip from that range.

Currently there is only one offense which we are monitoring for 

SSH bruteforcing 


Will eventually add in HTTP/s
POP etc etc 

