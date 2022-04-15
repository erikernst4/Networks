#!/usr/bin/env python3
import math
from scapy.all import *
S1 = {}

def mostrar_fuente(S):
    N = sum(S.values())
    simbolos = sorted(S.items(), key=lambda x: -x[1])
    prob_simbolos = [(apariciones/N) for d,apariciones in simbolos ]
    info_simbolos = [-math.log2(simbolo) for simbolo in prob_simbolos]
    print("\n".join([ " %s : %.5f | %.5f" % (simbolos[i][0], prob_simbolos[i], info_simbolos[i]) for i in range(len(simbolos))]))
    entropia = sum([prob_simbolos[simbolo] * info_simbolos[simbolo] for simbolo in range(len(simbolos))])
    print(f"Entropía de la fuente: {entropia} ")
    print()
    
def callback(pkt):
    if pkt.haslayer(Ether):
        dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
        proto = pkt[Ether].type # El campo type del frame tiene el protocolo
        s_i = (dire, proto) # Aca se define el simbolo de la fuente
        if s_i not in S1:
            S1[s_i] = 0.0
        S1[s_i] += 1.0
    mostrar_fuente(S1)

sniff(prn=callback)
