from scapy.all import *

# Establece el puerto que deseas capturar
PORT = 3030

def packet_callback(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == PORT:
        print(f"Packet captured: {packet.summary()}")  # Imprime un resumen del paquete
        # Puedes imprimir más detalles del paquete si lo deseas
        # print(packet.show())

# Captura paquetes en la interfaz de loopback
print(f"Capturando tráfico en localhost:{PORT}...")
sniff(filter=f'tcp port {PORT}', prn=packet_callback, store=0, iface='lo')
