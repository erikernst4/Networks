#!/usr/bin/env python3
import sys
import csv
import math
from scapy.all import *


S1 = {}

def mostrar_fuente():
    cant_muestras = sum(S1.values())
    simbolos = sorted(S1.items(), key=lambda x: -x[1])
    prob_simbolos = [(apariciones/cant_muestras) for d,apariciones in simbolos ]
    info_simbolos = [-math.log2(simbolo) for simbolo in prob_simbolos]
    print("\n".join([ " %s : %.5f | %.5f" % (simbolos[i][0], prob_simbolos[i], info_simbolos[i]) for i in range(len(simbolos))]))
    entropia = sum([prob_simbolos[simbolo] * info_simbolos[simbolo] for simbolo in range(len(simbolos))])
    print(f"Entropía de la fuente: {entropia} ")
    print()
    
def guardar_captura():
    columnas = S1.keys()
    with open('captura.csv', 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames = columnas)
            writer.writeheader()
            writer.writerows([S1])

def callback(pkt):
    if pkt.haslayer(Ether):
        dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
        proto = pkt[Ether].type # El campo type del frame tiene el protocolo
        s_i = (dire, proto) # Aca se define el simbolo de la fuente
        if s_i not in S1:
            S1[s_i] = 0.0
        S1[s_i] += 1.0
    mostrar_fuente()

def main():
    print("arrancó")

    tamaño_muestra = int(sys.argv[1])

    sniff(prn=callback, count=tamaño_muestra)

    guardar_captura()

if __name__ == "__main__":
        main()
