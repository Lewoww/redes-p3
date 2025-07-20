from iputils import read_ipv4_header
import ipaddress
import struct
from socket import IPPROTO_ICMP, IPPROTO_TCP

class IP:
    def __init__(self, enlace):
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela_encaminhamento = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, \
        frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        if dst_addr == self.meu_endereco:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            ttl -= 1
            if ttl <= 0:
                mensagem_icmp = self.tempo_excedido(datagrama)
                endereco_destino_resposta = src_addr
                datagrama_icmp = self._enviar_icmp(mensagem_icmp, endereco_destino_resposta)
                next_hop = self._next_hop(endereco_destino_resposta)
                self.enlace.enviar(datagrama_icmp, next_hop)
                return
            
            else:
                versao_e_tamanho_cabecalho = (4 << 4) | 5
                flags_e_frag_offset = (flags << 13) | frag_offset
                comprimento_total = len(datagrama)
                src_addr_empacotado = ipaddress.IPv4Address(src_addr).packed
                dst_addr_empacotado = ipaddress.IPv4Address(dst_addr).packed

                cabecalho_sem_checksum = struct.pack('!BBHHHBBH4s4s', versao_e_tamanho_cabecalho, (dscp << 2) | ecn, comprimento_total, identification, flags_e_frag_offset, ttl, proto, 0, src_addr_empacotado, dst_addr_empacotado)
                checksum_calculado = self.calcular_soma_verificacao(cabecalho_sem_checksum)

                cabecalho_novo = struct.pack('!BBHHHBBH4s4s', versao_e_tamanho_cabecalho, (dscp << 2) | ecn, comprimento_total,  identification, flags_e_frag_offset, ttl, proto, checksum_calculado,src_addr_empacotado, dst_addr_empacotado)

                datagrama_modificado = cabecalho_novo + payload
                next_hop = self._next_hop(dst_addr)
                self.enlace.enviar(datagrama_modificado, next_hop)

    def tempo_excedido(self, datagrama_expirado):
        checksum_icmp = 0
        campo_nao_utilizado = 0
        tipo_icmp = 11
        codigo_icmp = 0
        cabecalho_ip_original = datagrama_expirado[:20]
        payload_original = datagrama_expirado[20:28]
        payload_icmp = cabecalho_ip_original + payload_original
        cabecalho_icmp_parcial = struct.pack('!BBHI', tipo_icmp, codigo_icmp, checksum_icmp, campo_nao_utilizado)
        checksum_final = self.calcular_soma_verificacao(cabecalho_icmp_parcial + payload_icmp)
        cabecalho_icmp_completo = struct.pack('!BBHI', tipo_icmp, codigo_icmp, checksum_final, campo_nao_utilizado)

        return cabecalho_icmp_completo + payload_icmp

    def _enviar_icmp(self, mensagem_icmp, dest_addr_icmp):
        comprimento_total_icmp = 20 + len(mensagem_icmp)
        versao_e_tamanho_cabecalho_icmp = (4 << 4) | 5
        dscp_icmp = 0
        flags_icmp = 0
        frag_offset_icmp = 0
        ecn_icmp = 0
        proto_icmp = IPPROTO_ICMP
        checksum_ip = 0
        identification_icmp = 0
        ttl_icmp = 64
        src_addr_empacotado_icmp = ipaddress.IPv4Address(self.meu_endereco).packed
        dest_addr_empacotado_icmp = ipaddress.IPv4Address(dest_addr_icmp).packed

        cabecalho_ip_parcial = struct.pack('!BBHHHBBH4s4s', versao_e_tamanho_cabecalho_icmp, (dscp_icmp << 2) | ecn_icmp, comprimento_total_icmp, identification_icmp, (flags_icmp << 13) | frag_offset_icmp, ttl_icmp, proto_icmp, checksum_ip, src_addr_empacotado_icmp, dest_addr_empacotado_icmp)
        checksum_ip_final = self.calcular_soma_verificacao(cabecalho_ip_parcial)
        cabecalho_ip_completo = struct.pack('!BBHHHBBH4s4s', versao_e_tamanho_cabecalho_icmp, (dscp_icmp << 2) | ecn_icmp, comprimento_total_icmp, identification_icmp, (flags_icmp << 13) | frag_offset_icmp, ttl_icmp, proto_icmp, checksum_ip_final, src_addr_empacotado_icmp, dest_addr_empacotado_icmp)
        datagrama_icmp_final = cabecalho_ip_completo + mensagem_icmp
        return datagrama_icmp_final
        
    def _next_hop(self, dest_addr):

        ip_destino_obj = ipaddress.IPv4Address(dest_addr)
        melhor_correspondencia = None
        for rota_cidr, next_hop in self.tabela_encaminhamento:
            rede = ipaddress.IPv4Network(rota_cidr)
            if ip_destino_obj in rede:
                if(melhor_correspondencia is None or (rede.prefixlen > ipaddress.IPv4Network(melhor_correspondencia[0]).prefixlen)):
                    melhor_correspondencia = (rota_cidr, next_hop)

        if melhor_correspondencia:
            return melhor_correspondencia[1]
        else:
            return None
        
    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        self.tabela_encaminhamento = tabela

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        next_hop = self._next_hop(dest_addr)
        if not next_hop:
            return
        versao_e_tamanho_cabecalho_envio = (4 << 4) | 5
        comprimento_total_envio = 20 + len(segmento)
        identification_envio = 0
        dscp_envio = 0
        ecn_envio = 0
        proto_envio = IPPROTO_TCP
        checksum_envio = 0
        flags_envio = 0
        frag_offset_envio = 0
        ttl_envio = 64
        src_addr_empacotado_envio = ipaddress.IPv4Address(self.meu_endereco).packed
        dest_addr_empacotado_envio = ipaddress.IPv4Address(dest_addr).packed
        
        cabecalho_parcial_envio = struct.pack('!BBHHHBBH4s4s', versao_e_tamanho_cabecalho_envio, (dscp_envio << 2) | ecn_envio, comprimento_total_envio, identification_envio, (flags_envio << 13) | frag_offset_envio, ttl_envio, proto_envio, checksum_envio, src_addr_empacotado_envio, dest_addr_empacotado_envio)
        checksum_final_envio = self.calcular_soma_verificacao(cabecalho_parcial_envio)
        cabecalho_completo_envio = struct.pack('!BBHHHBBH4s4s', versao_e_tamanho_cabecalho_envio, (dscp_envio << 2) | ecn_envio, comprimento_total_envio, identification_envio, (flags_envio << 13) | frag_offset_envio, ttl_envio, proto_envio, checksum_final_envio, src_addr_empacotado_envio, dest_addr_empacotado_envio)
    
        datagrama = cabecalho_completo_envio + segmento
        self.enlace.enviar(datagrama, next_hop)

    def calcular_soma_verificacao(self, dados_cabecalho):
        
        if len(dados_cabecalho) % 2 == 1:
            dados_cabecalho += b'\0'
        soma = sum(struct.unpack("!%dH" % (len(dados_cabecalho) // 2), dados_cabecalho))
        soma = (soma >> 16) + (soma & 0xffff)
        soma += soma >> 16
        return ~soma & 0xffff
