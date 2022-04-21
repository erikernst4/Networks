# coding=utf-8
import sys
import csv
import math
import time
import pandas as pd
from scapy.all import *


S1 = {}

def mostrar_fuente():
    cant_muestras = sum(S1.values())
    simbolos = sorted(S1.items(), key=lambda x: -x[1])
    prob_simbolos = [(apariciones/cant_muestras) for d,apariciones in simbolos ]
    info_simbolos = [-math.log2(simbolo) for simbolo in prob_simbolos]
    print("\n".join([ " %s : %.5f | %.5f" % (simbolos[i][0], prob_simbolos[i], info_simbolos[i]) for i in range(len(simbolos))]))
    entropia = sum([prob_simbolos[simbolo] * info_simbolos[simbolo] for simbolo in range(len(simbolos))])
    print(f"Entropía de la fuente: {entropia}")
    print()
    
def guardar_captura(id_captura, time_obj):
    """
    columnas = S1.keys()
    with open('captura.csv', 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames = columnas)
            writer.writeheader()
            writer.writerows([S1])
    """
    results = []
    for simbolo in S1.keys():
        apariciones = S1[simbolo]
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
    mostrar_fuente()

def main():
    print("Inició la captura")

    tamaño_muestra = int(sys.argv[1])

    id_captura = sys.argv[2]

    time_obj = time.localtime()

    sniff(prn=callback, count=tamaño_muestra)

    guardar_captura(id_captura, time_obj)

if __name__ == "__main__":
        main()
