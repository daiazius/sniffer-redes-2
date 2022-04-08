import struct
import socket
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '

TAB_DADO_1 = '\t '
TAB_DADO_2 = '\t\t '
TAB_DADO_3 = '\t\t\t '


# Sniffer
def main():
    # socket.ntohs(3) = permite a compatibilidade com todas as maquinas

    conexao = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print('-------------------------------------------------------------------------------------------------------')
    # Loop infinito que recebe todos os pacotes que chegam
    while True:
        dado_bruto, endrc = conexao.recvfrom(65536)
        mac_dest, mac_orgm, eth_proto, dados = quadro_ethernet(dado_bruto)
        print('\nQuadro Ethernet:')
        print(TAB_1 + 'MAC Destino: {}, MAC Origem: {}, Protocolo: {}'.format(mac_dest, mac_orgm, eth_proto))

        # Protocolo Ethernet 8 = IPv4
        if eth_proto == 8:
            (versao, length_cabecalho, ttl, ip_proto, orgm, dest, dados) = pacote_ipv4(dados)
            print('Protocolo IPv4:')
            print(TAB_1 + 'Versao: {}, Comprimento Header: {}, TTL: {}'.format(versao, length_cabecalho, ttl))
            print(TAB_1 + 'Protocolo: {}, Origem: {}, Destino: {}'.format(ip_proto, orgm, dest))

            # ICMP
            if ip_proto == 1:
                tipo_icmp, codigo, checksum, dados = pacote_icmp(dados)
                print(TAB_1 + 'Pacote ICMP:')
                print(TAB_2 + 'Tipo: {}, Codigo: {}, Checksum: {},'.format(tipo_icmp, codigo, checksum))
                print(TAB_2 + 'Dados:')
                print(format_multi_line(TAB_DADO_3, dados))

            # TCP
            elif ip_proto == 6:
                (porta_orgm, porta_dest, sequencia, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin,
                 dados) = segmento_tcp(dados)
                print(TAB_1 + 'Segmento TCP:')
                print(TAB_2 + 'Porta Origem: {}, Porta Destino: {}'.format(porta_orgm, porta_dest))
                print(TAB_2 + 'Sequencia: {}, Acknowledgment: {},'.format(sequencia, ack))
                print(TAB_2 + 'Flags:')
                print(
                    TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh,
                                                                                          flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Dados:')
                print(format_multi_line(TAB_DADO_3, dados))

            # UDP
            elif ip_proto == 17:
                porta_orgm, porta_dest, comprimento, dados = segmento_udp(dados)
                print(TAB_1 + 'Segmento UDP:')
                print(TAB_2 + 'Porta Origem: {}, Porta Destino: {}, Comprimento: {}'.format(porta_orgm, porta_dest,
                                                                                            comprimento))

            # Outros
            else:
                print(TAB_1 + 'Dados:')
                print(format_multi_line(TAB_DADO_2, dados))

        else:
            print('Dados:')
            print(format_multi_line(TAB_DADO_1, dados))
        print(
            '\n-------------------------------------------------------------------------------------------------------')


# Desempacotar quadro Ethernet.
# !: network byte order (= big-endian), 6s: char[6], H: unsigned short
def quadro_ethernet(dados):
    mac_dest, mac_orgm, proto = struct.unpack('! 6s 6s H', dados[:14])
    return get_endrc_mac(mac_dest), get_endrc_mac(mac_orgm), socket.htons(proto), dados[14:]


# Função que retorna endereço MAC formatado. Ex: AA:BB:CC:DD:EE:FF
def get_endrc_mac(bytes_endrc):
    bytes_str = map('{:02x}'.format, bytes_endrc)
    return ':'.join(bytes_str).upper()


# Desempacotar pacote IPv4
# !: network byte order (= big-endian), x: pad byte, 4s: char[4], B: unsigned char
def pacote_ipv4(dados):
    versao_length_cabecalho = dados[0]
    versao = versao_length_cabecalho >> 4
    length_cabecalho = (versao_length_cabecalho & 15) * 4
    ttl, ip_proto, orgm, dest = struct.unpack('! 8x B B 2x 4s 4s', dados[:20])
    return versao, length_cabecalho, ttl, ip_proto, ipv4(orgm), ipv4(dest), dados[length_cabecalho:]


# Funcao que retorna endereco IPv4 formatado. Ex: 127.0.0.1
def ipv4(endrc):
    return '.'.join(map(str, endrc))


# Desempacotar pacote ICMP
# !: network byte order (= big-endian), B: unsigned char, H: unsigned short 
def pacote_icmp(dados):
    tipo_icmp, codigo, checksum = struct.unpack('! B B H', dados[:4])
    return tipo_icmp, codigo, checksum, dados[4:]


# Desempacotar segmento TCP
# !: network byte order (= big-endian), H: unsigned short, L: unsigned long
def segmento_tcp(dados):
    (porta_orgm, porta_dest, sequencia, ack, offset_reservados_flags) = struct.unpack('! H H L L H', dados[:14])
    offset = (offset_reservados_flags >> 12) * 4
    flag_urg = (offset_reservados_flags & 32) >> 5
    flag_ack = (offset_reservados_flags & 16) >> 4
    flag_psh = (offset_reservados_flags & 8) >> 3
    flag_rst = (offset_reservados_flags & 4) >> 2
    flag_syn = (offset_reservados_flags & 2) >> 1
    flag_fin = offset_reservados_flags & 1
    return porta_orgm, porta_dest, sequencia, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, dados[
                                                                                                               offset:]


# Desempacotar segmento UDP
# !: network byte order (= big-endian), H: unsigned short, x: pad byte
def segmento_udp(dados):
    porta_orgm, porta_dest, tamanho = struct.unpack('! H H 2x H', dados[:8])
    return porta_orgm, porta_dest, tamanho, dados[8:]


# Formatar dados para ficar em varias linhas
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
