import os
from scapy.all import sniff, IP, TCP, Raw, send

# Listas para almacenar los paquetes
client_packets = []
server_packets = []
captured_packets = []

# Banderas de control
running = True

def detener_sniffer():
    global running
    running = False
    print("Sniffer detenido.")

# Función que se ejecuta por cada paquete capturado
def captura_paquete(paquete):
    global running

    # Clasificar los paquetes según su origen y destino
    if TCP in paquete:
        if paquete[IP].src == "127.0.0.1" and paquete[TCP].sport == 3030 and (paquete[TCP].flags & 0x18 == 0x18):
            print("Paquete del servidor capturado.")
            server_packets.append(paquete)
        elif paquete[IP].dst == "127.0.0.1" and paquete[TCP].dport == 3030 and (paquete[TCP].flags & 0x18 == 0x18):
            print("Paquete del cliente capturado.")
            client_packets.append(paquete)
        
        captured_packets.append(paquete)

        # Mostrar un resumen del paquete capturado en pantalla
        print(f"Paquete capturado: {paquete.summary()}")  # Puedes usar paquete.show() para más detalles
    
    if not running:
        return False  # Detener el sniffer


def sniffer():
    print("Capturando tráfico en localhost:3030... (escribe 'stop' para detener)")
    
    while running:
        sniff(iface="lo", filter="tcp port 3030", prn=captura_paquete, stop_filter=lambda x: not running, timeout=1)

def visualizar_paquete(paquete):
    print(f"Paquete capturado: {paquete.summary()}")

def modificar_paquete(paquete):
    # Aquí podrías modificar el paquete según tus necesidades
    # Por ejemplo, podrías cambiar el payload del paquete
    if Raw in paquete:
        paquete[Raw].load = b"Modificado!"
        del paquete[IP].chksum  # Recalcular checksum
        del paquete[TCP].chksum
    return paquete

def main():
    global running

    # Iniciar el sniffer en un hilo separado
    try:
        from threading import Thread
        sniffer_thread = Thread(target=sniffer)
        sniffer_thread.start()

        # Esperar al comando 'stop' para detener el sniffer
        while running:
            comando = input().strip().lower()
            if comando == 'stop':
                detener_sniffer()
                sniffer_thread.join()

        # Imprimir los paquetes capturados
        print("\nPaquetes enviados por el cliente:")
        for i, packet in enumerate(client_packets):
            print(f"{i}: {packet.summary()}")

        print("\nPaquetes enviados por el servidor:")
        for i, packet in enumerate(server_packets):
            print(f"{i + len(client_packets)}: {packet.summary()}")

        # Seleccionar un paquete para modificar y reenviar
        if client_packets or server_packets:
            try:
                index = int(input("Selecciona el índice del paquete que deseas modificar y reenviar: "))
                if index < len(captured_packets):
                    packet_to_replay = captured_packets[index]

                    # Visualizar el paquete
                    visualizar_paquete(packet_to_replay)

                    # Preguntar si desea reenviar
                    resend = input("¿Desea reenviar el paquete (y/n)? ").strip().lower()
                    if resend == 'y':
                        # Modificar el paquete
                        modified_packet = modificar_paquete(packet_to_replay)
                        print("Modificando y reenviando el paquete...")

                        # Enviar el paquete modificado
                        send(modified_packet)
                        print("Paquete reenviado al servidor.")
                    elif resend == 'n':
                        os.system('clear' if os.name == 'posix' else 'cls')  # Limpiar pantalla
                    else:
                        print("Opción no válida.")
                else:
                    print("Índice inválido.")
            except ValueError:
                print("Entrada no válida.")
    except KeyboardInterrupt:
        detener_sniffer()

if __name__ == "__main__":
    main()
