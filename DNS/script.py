#!/usr/bin/env python3

from scapy.all import *

dns = DNS(rd=1,qd=DNSQR(qname="www.dc.uba.ar", qtype="MX"))
udp = UDP(sport=RandShort(), dport=53)
ip = IP(dst="198.41.0.4")

answer = sr1( ip / udp / dns , verbose=0, timeout=10)

if answer is not None and answer.haslayer(DNS) and answer[DNS].qd.qtype == 1:
    print("AUTHORITY")
    for i in range( answer[DNS].arcount):
        print (answer[DNS].ar[i].rrname, answer[DNS].ar[i].rdata)
    print ("NAME SERVERS")
    for i in range( answer[DNS].nscount):
        print (answer[DNS].ns[i].rrname, answer[DNS].ns[i].rdata)
    print ("ANSWER")
    for i in range( answer[DNS].ancount):
        print (answer[DNS].an[i].rrname, answer[DNS].an[i].rdata)
