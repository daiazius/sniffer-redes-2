import struct
import socket
import textwrap


# Sniffer
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        dado_bruto, endrc = conn.recvfrom(65536)
        mac_dest, mac_orgm, eth_proto, dados = quadro_ethernet(dado_bruto)
        print('\nQuadro Ethernet:')
        print('Destino: {}, Origem: {}, Protocolo: {}'.format(mac_dest, mac_orgm, eth_proto))


# Desempacotar quadro Ethernet
def quadro_ethernet(dados):
    mac_dest, mac_orgm, proto = struct.unpack('! 6s 6s H', dados[:14])
    return get_endrc_mac(mac_dest), get_endrc_mac(mac_orgm), socket.htons(proto), dados[14:]


# Função que retorna endereço MAC formatado. Ex: AA:BB:CC:DD:EE:FF
def get_endrc_mac(bytes_endrc):
    bytes_str = map('{:02x}'.format, bytes_endrc)
    return ':'.join(bytes_str).upper()


main()
