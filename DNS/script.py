#!/usr/bin/env python3

import sys
from scapy.all import *

types = {
    1 : "A",
    28 : "AAAA",
    2 : "NS",
    15 : "MX"
}

def DNSScan(queryIP, requestedHostname, queriedType = 15):

    print()
    print(queryIP, requestedHostname, queriedType)

    dns = DNS(rd=1,qd=DNSQR(qname=requestedHostname, qtype=queriedType))
    udp = UDP(sport=RandShort(), dport=53)
    ip = IP(dst=queryIP)

    answer = sr1( ip / udp / dns , verbose=0, timeout=10)

    if not answer.haslayer(DNS):
        print("An error has occured")
        return

    # Registro SOA
    if answer[DNS].nscount >= 1 and answer[DNS].ns[0].type == 6:
        print("A SOA record has been returned")
        return

    # Se tiene una respuesta
    if (answer[DNS].ancount >= 1):
        print("An answer has been found")
        final_answer = []
        for i in range(answer[DNS].ancount):
            if answer[DNS].an[i].type == 15:
                final_answer.append((answer[DNS].an[i].exchange, "MX", answer[DNS].an[i].rrname.decode("utf-8")))
            else: 
                final_answer.append((answer[DNS].an[i].rdata, types[answer[DNS].an[i].type], answer[DNS].an[i].rrname.decode("utf-8")))
        for ans in final_answer:
            print(ans)
        return final_answer

    # Si no hubo respuesta, busco la IP de algun Name Server
    print("Siguiente dominio: " + str(answer[DNS].ns[0].rrname.decode("utf-8")))
    
    #ipFound = False
    nextIP = 0
    nextNS = ""
    for i in range(answer[DNS].nscount):
        for j in range(answer[DNS].arcount):
            if answer[DNS].ns[i].rdata == answer[DNS].ar[j].rrname and answer[DNS].ar[j].type == 1:
                nextNS = answer[DNS].ns[i].rdata.decode("utf-8")
                nextIP = answer[DNS].ar[j].rdata
                print("Siguiente NS: " + str(nextNS))
                res = DNSScan(nextIP, requestedHostname, queriedType)
                if not res is None:
                    #ipFound = True
                    return res
                else:
                    print("Saliendo de recursion, volviendo para atras")

    """
    # Si la IP de algun Name Server no estaba en los additional records, la busco
    if not ipFound:
        print("--------RECURSIVE SEARCH FOR NS IP--------")
        for i in range(answer[DNS].nscount):
            recursive_answers = DNSScan("8.8.8.8", answer[DNS].ns[i].rdata, 1)
            for ans in recursive_answers:
                if ans[1] == "A" and ans[2] == answer[DNS].ns[i].rdata.decode("utf-8"):
                    nextNS = answer[DNS].ns[i].rdata.decode("utf-8")
                    nextIP = ans[0]
                    print("Siguiente NS: " + str(nextNS))
                    res = DNSScan(nextIP, requestedHostname, queriedType)
                    if not res is None:
                        return res
                    else:
                        print("Saliendo de recursion, volviendo para atras")
    """                        
    return res

DNSScan(sys.argv[1], sys.argv[2])