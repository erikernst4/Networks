# coding=utf-8
import sys
import csv
import math
import time
import pandas as pd
from scapy.all import *


S1 = {}

def mostrar_fuente(model_dict):
    cant_muestras = sum(model_dict.values())
    simbolos = sorted(model_dict.items(), key=lambda x: -x[1])
    prob_simbolos = [(apariciones/cant_muestras) for d,apariciones in simbolos ]
    info_simbolos = [-math.log2(simbolo) for simbolo in prob_simbolos]
    print("\n".join([ " %s : %.5f | %.5f" % (simbolos[i][0], prob_simbolos[i], info_simbolos[i]) for i in range(len(simbolos))]))
    entropia = sum([prob_simbolos[simbolo] * info_simbolos[simbolo] for simbolo in range(len(simbolos))])
    print(f"Entropía de la fuente: {entropia}")
    print()
    
def guardar_captura(id_captura, time_obj, model_dict):
    """
    columnas = S1.keys()
    with open('captura.csv', 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames = columnas)
            writer.writeheader()
            writer.writerows([S1])
    """
    results = []
    for simbolo in model_dict.keys():
        apariciones = model_dict[simbolo]
        results.append([simbolo, apariciones])
    df_results = pd.DataFrame(results, columns=["simbolo", "apariciones"])
    df_results.to_csv(f"./results/captura_{id_captura}_{time_obj.tm_hour}:{time_obj.tm_min}_{time_obj.tm_mday}-{time_obj.tm_mon}-{time_obj.tm_year}.csv")

def callback(pkt):
    if pkt.haslayer(Ether):
        dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
        proto = pkt[Ether].type # El campo type del frame tiene el protocolo
        s_i = (dire, proto) # Aca se define el simbolo de la fuente
        if s_i not in S1:
            S1[s_i] = 0.0
        S1[s_i] += 1.0
    mostrar_fuente(S1)

S2 = {}

def s2_callback(pkt):
    #https://scapy.readthedocs.io/en/latest/api/scapy.layers.l2.html?highlight=arp#id1
    if ARP in pkt and pkt[ARP].op in (1, 2): #who-is and is-at
        source_ip = pkt[ARP].psrc
        destiny_ip = pkt[ARP].pdst
        simbolo = (source_ip, destiny_ip)
        if simbolo not in S2:
            S2[simbolo] = 0.0
        S2[simbolo] += 1.0
        mostrar_fuente(S2)


def main():
    print("Inició la captura")
    if "-s2" == str(sys.argv[1]):
        tamaño_muestra = int(sys.argv[2])

        id_captura = sys.argv[3]

        time_obj = time.localtime()

        sniff(prn=s2_callback, count= tamaño_muestra, filter="arp", store=0)

        guardar_captura(id_captura, time_obj, S2)
    else: # s1
        tamaño_muestra = int(sys.argv[1])

        id_captura = sys.argv[2]

        time_obj = time.localtime()

        sniff(prn=callback, count=tamaño_muestra)

        guardar_captura(id_captura, time_obj, S1)

if __name__ == "__main__":
        main()
